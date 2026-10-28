/* Copyright (c) 2026 Canonical, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <errno.h>
#include <linux/neighbour.h>
#include <net/if.h>

#include "dp-packet.h"
#include "openvswitch/list.h"
#include "lib/mac-binding-index.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/vec.h"
#include "lport.h"
#include "mac-cache.h"
#include "neighbor-exchange-netlink.h"
#include "netdev.h"
#include "ovn-netlink-notifier.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "route-exchange.h"
#include "route-neighbor.h"
#include "openvswitch/shash.h"
#include "timeval.h"
#include "vec.h"

VLOG_DEFINE_THIS_MODULE(route_neighbor);

#define RN_REPAIR_MSEC 1000
#define RN_REFRESH_MSEC 30000
#define RN_MAX_PROBES 8

/* One dynamic cache key.  These runtime records are not leases on SB rows:
 * residency and row identity must still be checked before every write. */
struct route_neighbor {
    struct hmap_node node;
    char *port;
    struct in6_addr ip;
    struct uuid pb_uuid;
    struct uuid dp_uuid;
    char ifname[IFNAMSIZ + 1];
    int ifindex;
    struct eth_addr source_mac;
    ovs_be32 source_ip;
    bool seen;
    bool confirming;
    bool identity_changed;
    bool retired;
    long long retired_until;
    long long activated;
    struct eth_addr hint_mac;
    long long epoch;
    long long next_probe;
    long long last_probe;
    long long backoff;
    struct eth_addr last_mac;
    struct uuid mb_uuid;
    long long mb_timestamp;
    bool written;
    bool committed;
};

struct route_neighbor_state {
    struct hmap entries;
    /* Hold netdevs even while a candidate has no host IPv4 address yet.
     * The provider needs live devices to invalidate its address snapshot. */
    struct shash devices;
    struct ovsdb_idl_index *pb_by_name;
    struct uuid chassis_uuid;
    long long next_run;
    bool dirty;
    bool have_candidates;
    size_t probe_cursor;
};

struct route_neighbor_device {
    struct netdev *netdev;
    bool seen;
};

/* A snapshot, including any dump error, belongs to one reconciliation pass.
 * Key it by interface index so routes using the same interface share it. */
struct route_neighbor_snapshot {
    struct hmap_node node;
    int ifindex;
    struct vector neighbors;
    int error;
    long long when_msec;
    long long when_wall_msec;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

static uint32_t
rn_hash(const char *port, const struct in6_addr *ip)
{
    return hash_bytes(ip, sizeof *ip, hash_string(port, 0));
}

static struct route_neighbor *
rn_find(struct route_neighbor_state *state, const char *port,
        const struct in6_addr *ip)
{
    struct route_neighbor *rn;
    HMAP_FOR_EACH_WITH_HASH (rn, node, rn_hash(port, ip), &state->entries) {
        if (!strcmp(rn->port, port) && ipv6_addr_equals(&rn->ip, ip)) {
            return rn;
        }
    }
    return NULL;
}

static bool
rn_active(const struct route_neighbor_state *state,
          const struct sbrec_port_binding *pb)
{
    if (!pb || !state->pb_by_name) {
        return false;
    }
    const struct sbrec_port_binding *cr =
        lport_get_cr_port(state->pb_by_name, pb, NULL);
    const struct sbrec_port_binding *owner = cr ? cr : pb;
    return owner->chassis &&
           uuid_equals(&owner->chassis->header_.uuid, &state->chassis_uuid);
}

static bool
rn_addressless(const struct sbrec_port_binding *pb)
{
    if (!pb->n_mac || smap_get_bool(&pb->options,
                                   "dynamic-routing-no-learning", false)) {
        return false;
    }
    struct lport_addresses addresses;
    if (!extract_lsp_addresses(pb->mac[0], &addresses)) {
        return false;
    }
    bool addressless = !addresses.n_ipv4_addrs;
    destroy_lport_addresses(&addresses);
    return addressless;
}

static bool
rn_mapped(struct route_neighbor_state *state,
           const struct sbrec_port_binding *pb)
{
    const struct sbrec_port_binding *cr =
        lport_get_cr_port(state->pb_by_name, pb, NULL);
    const char *name = smap_get(&pb->options, "dynamic-routing-port-name");
    if (!name && cr) {
        name = smap_get(&cr->options, "dynamic-routing-port-name");
    }
    return name && name[0];
}

static const struct sbrec_port_binding *
rn_current_port(struct route_neighbor_state *state,
                const struct route_neighbor *rn)
{
    const struct sbrec_port_binding *pb =
        lport_lookup_by_name(state->pb_by_name, rn->port);
    return pb && uuid_equals(&pb->header_.uuid, &rn->pb_uuid) &&
           uuid_equals(&pb->datapath->header_.uuid, &rn->dp_uuid) &&
           rn_active(state, pb) && rn_addressless(pb) && rn_mapped(state, pb)
           ? pb : NULL;
}

/* Verify the local binding as part of the transaction as well as checking its
 * current value.  HA membership alone does not authorize MAC publication. */
static void
rn_verify_port(struct route_neighbor_state *state,
               const struct sbrec_port_binding *pb)
{
    sbrec_port_binding_verify_datapath(pb);
    sbrec_port_binding_verify_mac(pb);
    sbrec_port_binding_verify_options(pb);
    const struct sbrec_port_binding *cr =
        lport_get_cr_port(state->pb_by_name, pb, NULL);
    sbrec_port_binding_verify_chassis(cr ? cr : pb);
    if (cr) {
        sbrec_port_binding_verify_options(cr);
    }
}

static void
rn_remove(struct route_neighbor_state *state, struct route_neighbor *rn)
{
    hmap_remove(&state->entries, &rn->node);
    free(rn->port);
    free(rn);
}

/* Observe a committed row before treating a previous write as ours.  This
 * also handles a transaction that committed but lost its acknowledgment. */
static void
rn_check_committed(struct route_neighbor *rn,
                   const struct sbrec_mac_binding_table *table)
{
    if (!rn->written) {
        return;
    }
    const struct sbrec_mac_binding *mb =
        sbrec_mac_binding_table_get_for_uuid(table, &rn->mb_uuid);
    struct in6_addr ip;
    char mac[ETH_ADDR_STRLEN + 1];
    snprintf(mac, sizeof mac, ETH_ADDR_FMT, ETH_ADDR_ARGS(rn->last_mac));
    rn->committed = mb && !strcmp(mb->logical_port, rn->port) &&
                    uuid_equals(&mb->datapath->header_.uuid, &rn->dp_uuid) &&
                    ip46_parse(mb->ip, &ip) &&
                    ipv6_addr_equals(&ip, &rn->ip) &&
                    !strcmp(mb->mac, mac) && mb->timestamp == rn->mb_timestamp;
}

static void
rn_delete_recorded(struct route_neighbor_state *state,
                   struct route_neighbor *rn,
                   const struct sbrec_mac_binding_table *table)
{
    const struct sbrec_port_binding *pb = rn_current_port(state, rn);
    if (!rn->committed || !pb) {
        return;
    }
    const struct sbrec_mac_binding *mb =
        sbrec_mac_binding_table_get_for_uuid(table, &rn->mb_uuid);
    if (mb) {
        rn_verify_port(state, pb);
        sbrec_mac_binding_verify_logical_port(mb);
        sbrec_mac_binding_verify_ip(mb);
        sbrec_mac_binding_verify_datapath(mb);
        sbrec_mac_binding_verify_mac(mb);
        sbrec_mac_binding_verify_timestamp(mb);
        sbrec_mac_binding_delete(mb);
    }
    /* A queued delete is tentative.  Keep the recorded identity until a
     * later IDL snapshot proves that it disappeared or changed, so a failed
     * transaction can retry the same guarded deletion. */
}

static bool
rn_valid_nexthop(const struct route_next_hop *nh)
{
    if (!IN6_IS_ADDR_V4MAPPED(&nh->addr)) {
        return false;
    }
    ovs_be32 ip = in6_addr_get_mapped_ipv4(&nh->addr);
    return ip && ip != OVS_BE32_MAX && !ip_is_multicast(ip) &&
           (ntohl(ip) >> 24) != 127;
}

/* Read host identity without configuring the device or the neighbor cache. */
static bool
rn_host(struct route_neighbor_state *state, const struct route_next_hop *nh,
         struct route_neighbor *identity)
{
    ovs_be32 ip = in6_addr_get_mapped_ipv4(&nh->addr);
    struct route_neighbor_device *device =
        shash_find_data(&state->devices, nh->ifname);
    if (!device) {
        struct netdev *dev;
        if (netdev_open(nh->ifname, NULL, &dev)) {
            return false;
        }
        device = xzalloc(sizeof *device);
        device->netdev = dev;
        shash_add(&state->devices, nh->ifname, device);
    }
    device->seen = true;
    struct netdev *dev = device->netdev;
    enum netdev_flags flags;
    struct in6_addr *addrs = NULL, *masks = NULL;
    int n_addrs = 0;
    bool ok = !netdev_get_flags(dev, &flags) && flags & NETDEV_UP &&
              !netdev_get_etheraddr(dev, &identity->source_mac) &&
              !eth_addr_is_zero(identity->source_mac) &&
              !eth_addr_is_multicast(identity->source_mac) &&
              !netdev_get_addr_list(dev, &addrs, &masks, &n_addrs);
    identity->ifindex = netdev_get_ifindex(dev);
    identity->source_ip = 0;
    for (int i = 0; ok && i < n_addrs; i++) {
        if (!IN6_IS_ADDR_V4MAPPED(&addrs[i])) {
            continue;
        }
        ovs_be32 addr = in6_addr_get_mapped_ipv4(&addrs[i]);
        ovs_be32 mask = in6_addr_get_mapped_ipv4(&masks[i]);
        if (!addr || ip_is_multicast(addr) || (ntohl(addr) >> 24) == 127) {
            continue;
        }
        if (ip == addr || (ip == (addr | ~mask) &&
                          ntohl(mask) < UINT32_C(0xfffffffe))) {
            ok = false;
            break;
        }
        if (!identity->source_ip || (ip & mask) == (addr & mask)) {
            identity->source_ip = addr;
        }
    }
    free(addrs);
    free(masks);
    return ok && identity->ifindex > 0 && identity->source_ip;
}

static const struct route_neighbor_snapshot *
rn_snapshot_get(struct hmap *snapshots, const struct route_neighbor *rn)
{
    uint32_t hash = hash_int(rn->ifindex, 0);
    struct route_neighbor_snapshot *snapshot;
    HMAP_FOR_EACH_WITH_HASH (snapshot, node, hash, snapshots) {
        if (snapshot->ifindex == rn->ifindex) {
            return snapshot;
        }
    }

    snapshot = xzalloc(sizeof *snapshot);
    snapshot->ifindex = rn->ifindex;
    snapshot->neighbors =
        VECTOR_EMPTY_INITIALIZER(struct ne_nl_received_neigh);
    /* Confirmation ages belong to this observation.  Anchor them before
     * the dump so applying the snapshot later cannot make it fresher. */
    snapshot->when_msec = time_msec();
    snapshot->when_wall_msec = time_wall_msec();
    snapshot->error = ne_nl_dump_neigh(AF_INET, rn->ifindex,
                                      &snapshot->neighbors);
    if (snapshot->error) {
        VLOG_WARN_RL(&rl, "Cannot read neighbors on %s: %s",
                     rn->ifname, ovs_strerror(snapshot->error));
    }
    hmap_insert(snapshots, &snapshot->node, hash);
    return snapshot;
}

/* Do not rewrite an existing entry's NUD state: an administrator could have
 * made it permanent since the snapshot.  Normal ARP reception preserves the
 * kernel's administrative-neighbor semantics. */
static int
rn_send_request(const struct route_neighbor *rn)
{
    struct netdev *dev;
    int error = netdev_open(rn->ifname, NULL, &dev);
    if (error) {
        return error;
    }
    if (netdev_get_ifindex(dev) != rn->ifindex || !netdev_n_txq(dev)) {
        netdev_close(dev);
        return ENODEV;
    }
    struct eth_addr mac;
    if (netdev_get_etheraddr(dev, &mac) ||
        !eth_addr_equals(mac, rn->source_mac)) {
        netdev_close(dev);
        return ENODEV;
    }
    struct dp_packet *packet = dp_packet_new(64);
    compose_arp(packet, ARP_OP_REQUEST, rn->source_mac, eth_addr_zero,
                true, rn->source_ip, in6_addr_get_mapped_ipv4(&rn->ip));
    struct dp_packet_batch batch;
    dp_packet_batch_init_packet(&batch, packet);
    error = netdev_send(dev, 0, &batch, false);
    netdev_close(dev);
    return error;
}

struct route_neighbor_state *
route_neighbor_create(void)
{
    struct route_neighbor_state *state = xzalloc(sizeof *state);
    hmap_init(&state->entries);
    shash_init(&state->devices);
    state->dirty = true;
    return state;
}

void
route_neighbor_destroy(struct route_neighbor_state *state)
{
    struct route_neighbor *rn;
    HMAP_FOR_EACH_SAFE (rn, node, &state->entries) {
        rn_remove(state, rn);
    }
    hmap_destroy(&state->entries);
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &state->devices) {
        struct route_neighbor_device *device = node->data;
        netdev_close(device->netdev);
        free(device);
        shash_delete(&state->devices, node);
    }
    shash_destroy(&state->devices);
    ovn_netlink_update_notifier(OVN_NL_NOTIFIER_ROUTE_NEIGHBOR, false);
    free(state);
}

bool
route_neighbor_wake(struct route_neighbor_state *state)
{
    return state && (state->dirty ||
        ((state->have_candidates || !hmap_is_empty(&state->entries)) &&
         time_msec() >= state->next_run) ||
        ovn_netlink_notifier_lost(OVN_NL_NOTIFIER_ROUTE_NEIGHBOR) ||
        !vector_is_empty(ovn_netlink_get_msgs(
            OVN_NL_NOTIFIER_ROUTE_NEIGHBOR)));
}

void
route_neighbor_wait(struct route_neighbor_state *state)
{
    if (state && (state->have_candidates || !hmap_is_empty(&state->entries))) {
        poll_timer_wait_until(state->next_run);
    }
}

/* Dataplane usage cannot confirm the Linux neighbor that owns this key. */
bool
route_neighbor_owns_binding(struct route_neighbor_state *state,
                            const struct sbrec_mac_binding *mb)
{
    struct in6_addr ip;
    if (!state || !mb || !ip46_parse(mb->ip, &ip)) {
        return false;
    }
    const struct sbrec_port_binding *pb = state->pb_by_name
        ? lport_lookup_by_name(state->pb_by_name, mb->logical_port) : NULL;
    const struct sbrec_port_binding *cr = pb
        ? lport_get_cr_port(state->pb_by_name, pb, NULL) : NULL;
    bool chassis_bound = pb &&
        (cr || pb->chassis || !strcmp(pb->type, "l3gateway"));
    /* Old statistics must not renew a shared uplink after this chassis loses
     * ownership, even after its route references and packet fence expire. */
    if (IN6_IS_ADDR_V4MAPPED(&ip) && chassis_bound &&
        smap_get(&pb->datapath->external_ids, "logical-router") &&
        rn_addressless(pb) &&
        rn_mapped(state, pb) && !rn_active(state, pb)) {
        return true;
    }
    struct route_neighbor *rn = rn_find(state, mb->logical_port, &ip);
    if (!rn || !uuid_equals(&rn->dp_uuid, &mb->datapath->header_.uuid)) {
        return false;
    }
    if (!rn->retired) {
        return true;
    }
    struct eth_addr mac;
    /* Retain the old-row statistics fence without claiming an edited row or
     * a new ordinary writer's binding after this key leaves resolver scope. */
    return rn->written && uuid_equals(&rn->mb_uuid, &mb->header_.uuid) &&
           eth_addr_from_string(mb->mac, &mac) &&
           eth_addr_equals(mac, rn->last_mac) &&
           mb->timestamp == rn->mb_timestamp;
}

bool
route_neighbor_observe(struct route_neighbor_state *state,
                       const struct sbrec_port_binding *pb,
                       const struct in6_addr *ip, struct eth_addr mac,
                       long long observed)
{
    if (!state || !pb) {
        return false;
    }
    struct route_neighbor *rn = rn_find(state, pb->logical_port, ip);
    if (!rn) {
        return false;
    }
    if (rn->retired) {
        return observed < rn->retired_until;
    }
    if (rn_current_port(state, rn) != pb ||
        observed < rn->activated) {
        return true;
    }
    bool conflicting = !eth_addr_is_zero(mac) &&
                       !eth_addr_equals(mac, rn->last_mac);
    if ((!rn->confirming && eth_addr_is_zero(mac)) ||
        (conflicting && (!rn->confirming ||
                         !eth_addr_equals(mac, rn->hint_mac)))) {
        rn->confirming = true;
        /* Cache ages have kernel tick precision.  The safety margin rejects
         * pre-hint confirmations from the same tick. */
        rn->epoch = time_msec() + 20;
        rn->hint_mac = mac;
        rn->next_probe = 0;
        state->dirty = true;
        poll_immediate_wake();
    }
    return true;
}

void
route_neighbor_run(struct route_neighbor_state *state,
                   struct ovsdb_idl_txn *txn, struct vector *next_hops,
                   struct ovsdb_idl_index *pb_by_name,
                   struct ovsdb_idl_index *mb_by_lport_ip,
                   const struct sbrec_mac_binding_table *mb_table,
                   const struct sbrec_chassis *chassis,
                   struct mac_cache_data *mac_cache, bool ready)
{
    state->pb_by_name = pb_by_name;
    if (chassis) {
        state->chassis_uuid = chassis->header_.uuid;
    } else {
        uuid_zero(&state->chassis_uuid);
    }
    state->dirty = false;
    long long now = time_msec();
    state->next_run = now + RN_REPAIR_MSEC;
    /* Keep state on incomplete route/IDL observations.  Publication and
     * cleanup resume only after a complete current snapshot is available. */
    if (!ready) {
        return;
    }
    state->have_candidates = false;
    struct shash_node *node;
    SHASH_FOR_EACH (node, &state->devices) {
        struct route_neighbor_device *device = node->data;
        device->seen = false;
    }

    struct route_neighbor *rn;
    HMAP_FOR_EACH (rn, node, &state->entries) {
        rn->seen = false;
        rn_check_committed(rn, mb_table);
    }
    const struct route_next_hop *nh;
    VECTOR_FOR_EACH_PTR (next_hops, nh) {
        const struct sbrec_port_binding *pb =
            lport_lookup_by_name(pb_by_name, nh->logical_port);
        struct route_neighbor identity;
        if (!pb || pb->datapath != nh->datapath || !rn_active(state, pb) ||
            !rn_addressless(pb) || !rn_mapped(state, pb) ||
            !rn_valid_nexthop(nh)) {
            continue;
        }
        if (!state->have_candidates) {
            /* Poll only eligible scope, including interfaces temporarily
             * down or without an IPv4 address.  Flush once before reading
             * host identities: no held netdev may have seen an address
             * change while there were no eligible routes. */
            state->have_candidates = true;
            netdev_get_addrs_list_flush();
        }
        if (!rn_host(state, nh, &identity)) {
            continue;
        }
        rn = rn_find(state, nh->logical_port, &nh->addr);
        if (rn && (!uuid_equals(&rn->pb_uuid, &pb->header_.uuid) ||
                   !uuid_equals(&rn->dp_uuid, &pb->datapath->header_.uuid))) {
            /* Rebuild a recreated port's scope in this pass, before buffered
             * native observations can be considered for its new binding. */
            rn_remove(state, rn);
            rn = NULL;
        }
        if (!rn) {
            rn = xzalloc(sizeof *rn);
            rn->port = xstrdup(nh->logical_port);
            rn->ip = nh->addr;
            rn->pb_uuid = pb->header_.uuid;
            rn->dp_uuid = pb->datapath->header_.uuid;
            rn->backoff = 1000;
            rn->activated = now;
            hmap_insert(&state->entries, &rn->node,
                        rn_hash(rn->port, &rn->ip));
        }
        if (rn->seen) {
            continue;
        }
        if (rn->retired) {
            rn->retired = false;
            rn->activated = now;
            rn->confirming = true;
            rn->identity_changed = true;
            rn->epoch = now + 20;
            rn->next_probe = 0;
        }
        if (rn->ifindex && (rn->ifindex != identity.ifindex ||
            !eth_addr_equals(rn->source_mac, identity.source_mac) ||
            rn->source_ip != identity.source_ip ||
            strcmp(rn->ifname, nh->ifname))) {
            rn->confirming = true;
            rn->identity_changed = true;
            rn->epoch = now + 20;
            rn->next_probe = 0;
        }
        rn->ifindex = identity.ifindex;
        rn->source_mac = identity.source_mac;
        rn->source_ip = identity.source_ip;
        ovs_strlcpy(rn->ifname, nh->ifname, sizeof rn->ifname);
        rn->seen = true;
    }
    SHASH_FOR_EACH_SAFE (node, &state->devices) {
        struct route_neighbor_device *device = node->data;
        if (!device->seen) {
            netdev_close(device->netdev);
            free(device);
            shash_delete(&state->devices, node);
        }
    }
    ovn_netlink_update_notifier(OVN_NL_NOTIFIER_ROUTE_NEIGHBOR,
                                !hmap_is_empty(&state->entries));
    ovn_netlink_notifier_flush(OVN_NL_NOTIFIER_ROUTE_NEIGHBOR);

    /* Rotate the bounded probe slots.  Fixed hmap order can otherwise starve
     * later keys when many unresolved peers reach their retry limit. */
    size_t n_entries = hmap_count(&state->entries);
    size_t ordinal = 0;
    size_t cursor = n_entries ? state->probe_cursor % n_entries : 0;
    state->probe_cursor = n_entries
        ? (cursor + RN_MAX_PROBES) % n_entries : 0;
    struct hmap snapshots = HMAP_INITIALIZER(&snapshots);
    HMAP_FOR_EACH_SAFE (rn, node, &state->entries) {
        bool probe_slot = (ordinal++ + n_entries - cursor) % n_entries
                          < RN_MAX_PROBES;
        const struct sbrec_port_binding *pb = rn_current_port(state, rn);
        if (!rn->seen || !pb) {
            if (rn->retired) {
                if (rn->committed && pb) {
                    if (txn) {
                        rn_delete_recorded(state, rn, mb_table);
                    }
                    /* Deletion also hides the row from transaction-local
                     * lookups.  Retain the intent until a later snapshot
                     * confirms its absence, not merely until it is queued. */
                    continue;
                }
                char *ip = normalize_v46(&rn->ip);
                const struct sbrec_mac_binding *mb =
                    mac_binding_lookup(mb_by_lport_ip, rn->port, ip);
                free(ip);
                /* Pending traffic statistics can outlive an SB outage.
                 * Keep fencing this key while its old datapath's row exists;
                 * statistics queued for a deleted UUID cannot renew a new
                 * row.  The minimum hold also drains packet observations. */
                if (now >= rn->retired_until &&
                    (!mb || !route_neighbor_owns_binding(state, mb))) {
                    rn_remove(state, rn);
                }
                continue;
            }
            if (!txn && pb) {
                continue;
            }
            if (txn) {
                rn_delete_recorded(state, rn, mb_table);
            }
            /* Native packet observations expire after one second.  Keep a
             * longer tombstone to distinguish former scope from an ordinary
             * unmanaged key while those buffers are drained. */
            rn->retired = true;
            rn->retired_until = now + 2000;
            continue;
        }
        const struct route_neighbor_snapshot *snapshot =
            rn_snapshot_get(&snapshots, rn);
        if (snapshot->error) {
            continue;
        }
        const struct ne_nl_received_neigh *neighbor = NULL, *n;
        VECTOR_FOR_EACH_PTR (&snapshot->neighbors, n) {
            if (n->if_index == rn->ifindex &&
                ipv6_addr_equals(&n->addr, &rn->ip)) {
                neighbor = n;
                break;
            }
        }
        bool valid_mac = neighbor && !eth_addr_is_zero(neighbor->lladdr) &&
                         !eth_addr_is_multicast(neighbor->lladdr) &&
                         !ne_is_ovn_owned(neighbor);
        bool permanent = valid_mac && neighbor->state & NUD_PERMANENT;
        bool confirmed = permanent ||
            (valid_mac && neighbor->state & NUD_REACHABLE &&
             (!rn->confirming || (neighbor->has_cacheinfo &&
              snapshot->when_msec - neighbor->confirmed_msec >= rn->epoch)));

        if (txn && rn->identity_changed && !confirmed) {
            /* An old link's MAC is not evidence for a replacement interface,
             * even when the new link already has an unconfirmed neighbor. */
            rn_delete_recorded(state, rn, mb_table);
        }

        struct mac_cache_threshold *threshold = mac_cache_threshold_find(
            mac_cache, pb->datapath->tunnel_key);
        long long refresh = threshold
            ? MAX(100, MIN(RN_REFRESH_MSEC, threshold->value / 4))
            : RN_REFRESH_MSEC;
        if (confirmed) {
            rn->confirming = false;
            rn->backoff = 1000;
            if (txn) {
                rn_verify_port(state, pb);
                char *ip = normalize_v46(&rn->ip);
                const struct sbrec_mac_binding *existing =
                    mac_binding_lookup(mb_by_lport_ip, rn->port, ip);
                if (existing) {
                    sbrec_mac_binding_verify_logical_port(existing);
                    sbrec_mac_binding_verify_ip(existing);
                    sbrec_mac_binding_verify_datapath(existing);
                    sbrec_mac_binding_verify_mac(existing);
                    sbrec_mac_binding_verify_timestamp(existing);
                    /* A recreated port can retain a same-key dynamic row
                     * until northd removes its old datapath reference.  Only
                     * current, confirmed scope may adopt that row. */
                    if (existing->datapath != pb->datapath) {
                        sbrec_mac_binding_set_datapath(existing, pb->datapath);
                    }
                }
                const struct sbrec_mac_binding *mb = mac_binding_add_to_sb(
                    txn, mb_by_lport_ip, rn->port, pb->datapath,
                    neighbor->lladdr, ip, false, NULL);
                free(ip);
                /* A fresh snapshot alone must not renew the timestamp. */
                long long confirmed_wall = snapshot->when_wall_msec -
                    (permanent ? 0 : neighbor->confirmed_msec);
                if ((permanent || neighbor->has_cacheinfo) &&
                    confirmed_wall > mb->timestamp + refresh &&
                    sbrec_server_has_mac_binding_table_col_timestamp(
                        ovsdb_idl_txn_get_idl(txn))) {
                    sbrec_mac_binding_set_timestamp(mb, confirmed_wall);
                }
                rn->mb_uuid = mb->header_.uuid;
                rn->mb_timestamp = mb->timestamp;
                rn->last_mac = neighbor->lladdr;
                rn->written = true;
                rn->identity_changed = false;
            }
        } else if (txn && (!neighbor || neighbor->state &
                            (NUD_FAILED | NUD_INCOMPLETE))) {
            /* An eligible key is under current resolver authority, including
             * after a restart.  Invalidate stale dynamic state, never static
             * overrides or unrelated keys. */
            char *ip = normalize_v46(&rn->ip);
            const struct sbrec_mac_binding *mb =
                mac_binding_lookup(mb_by_lport_ip, rn->port, ip);
            free(ip);
            if (mb && mb->datapath == pb->datapath) {
                rn_verify_port(state, pb);
                sbrec_mac_binding_verify_logical_port(mb);
                sbrec_mac_binding_verify_ip(mb);
                sbrec_mac_binding_verify_datapath(mb);
                sbrec_mac_binding_verify_mac(mb);
                sbrec_mac_binding_delete(mb);
                rn->written = rn->committed = false;
            }
        }
        if (!permanent && !(neighbor && neighbor->state & NUD_NOARP) &&
            probe_slot && now >= rn->next_probe &&
            (!confirmed || now - rn->last_probe >= refresh)) {
            int error;
            if (neighbor) {
                error = rn_send_request(rn);
            } else {
                error = ne_nl_resolve_neigh(rn->ifindex, &rn->ip);
            }
            if (error && error != EEXIST) {
                VLOG_DBG_RL(&rl, "Cannot resolve %s on %s: %s",
                             rn->port, rn->ifname, ovs_strerror(error));
            }
            if (!rn->confirming) {
                rn->confirming = true;
                rn->epoch = now + 20;
            }
            rn->last_probe = now;
            rn->next_probe = now + rn->backoff;
            rn->backoff = MIN(30000, rn->backoff * 2);
        }
    }
    struct route_neighbor_snapshot *snapshot;
    HMAP_FOR_EACH_POP (snapshot, node, &snapshots) {
        vector_destroy(&snapshot->neighbors);
        free(snapshot);
    }
    hmap_destroy(&snapshots);
}
