/* Copyright (c) 2026, Canonical Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
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

#include "lib/vec.h"
#include "controller/lport.h"
#include "controller/mac-cache.h"
#include "controller/neighbor-exchange-netlink.h"
#include "controller/ovn-netlink-notifier.h"
#include "controller/route-exchange.h"
#include "controller/route-neighbor.h"
#include "netdev.h"
#include "ovn-sb-idl.h"
#include "packets.h"
#include "tests/ovstest.h"
#include "timeval.h"

/* Exercise the reconciler without requiring host interfaces, a database, or
 * wall-clock delays.  Other ovstest commands use the real collaborators. */
static struct {
    bool active;
    long long now;
    unsigned int opens, flushes;
    struct sbrec_chassis chassis;
    struct sbrec_datapath_binding datapath;
    struct sbrec_port_binding ports[3];
    char *macs[3];
    struct vector next_hops;
    struct {
        bool up, addressed, present, populated;
        int error;
        unsigned int dumps, resolves;
    } devices[2];
} fixture;

#define WRAP_DECL(RET, NAME, ARGS) \
    RET __real_##NAME ARGS;        \
    RET __wrap_##NAME ARGS

WRAP_DECL(long long, time_msec, (void));
WRAP_DECL(const struct sbrec_port_binding *, lport_lookup_by_name,
          (struct ovsdb_idl_index *, const char *));
WRAP_DECL(int, netdev_open, (const char *, const char *, struct netdev **));
WRAP_DECL(void, netdev_close, (struct netdev *));
WRAP_DECL(int, netdev_get_flags, (const struct netdev *, enum netdev_flags *));
WRAP_DECL(int, netdev_get_etheraddr,
          (const struct netdev *, struct eth_addr *));
WRAP_DECL(int, netdev_get_addr_list,
          (const struct netdev *, struct in6_addr **, struct in6_addr **,
           int *));
WRAP_DECL(int, netdev_get_ifindex, (const struct netdev *));
WRAP_DECL(void, netdev_get_addrs_list_flush, (void));
WRAP_DECL(int, ne_nl_dump_neigh, (uint8_t, int32_t, struct vector *));
WRAP_DECL(int, ne_nl_resolve_neigh, (int32_t, const struct in6_addr *));
WRAP_DECL(void, ovn_netlink_update_notifier,
          (enum ovn_netlink_notifier_type, bool));

/* The fixture has no aging thresholds.  Avoid linking the whole packet-in
 * controller into ovstest for this collaborator; kernel tests use the real
 * MAC cache and exercise timestamp publication and aging. */
struct mac_cache_threshold *
mac_cache_threshold_find(struct mac_cache_data *data OVS_UNUSED,
                         uint32_t dp_key OVS_UNUSED)
{
    ovs_assert(fixture.active);
    return NULL;
}

static size_t
fixture_device(const struct netdev *dev)
{
    size_t i = (uintptr_t) dev - 1;
    ovs_assert(i < ARRAY_SIZE(fixture.devices));
    return i;
}

long long
__wrap_time_msec(void)
{
    return fixture.active ? fixture.now : __real_time_msec();
}

const struct sbrec_port_binding *
__wrap_lport_lookup_by_name(struct ovsdb_idl_index *index, const char *name)
{
    if (!fixture.active) {
        return __real_lport_lookup_by_name(index, name);
    }
    for (size_t i = 0; i < ARRAY_SIZE(fixture.ports); i++) {
        if (!strcmp(fixture.ports[i].logical_port, name)) {
            return &fixture.ports[i];
        }
    }
    return NULL;
}

int
__wrap_netdev_open(const char *name, const char *type, struct netdev **dev)
{
    if (!fixture.active) {
        return __real_netdev_open(name, type, dev);
    }
    fixture.opens++;
    size_t i = !strcmp(name, "uplink-a") ? 0 : 1;
    ovs_assert(!strcmp(name, i ? "uplink-b" : "uplink-a"));
    if (!fixture.devices[i].present) {
        return ENODEV;
    }
    *dev = (struct netdev *) (uintptr_t) (i + 1);
    return 0;
}

void
__wrap_netdev_close(struct netdev *dev)
{
    if (!fixture.active) {
        __real_netdev_close(dev);
    } else {
        fixture_device(dev);
    }
}

int
__wrap_netdev_get_flags(const struct netdev *dev, enum netdev_flags *flags)
{
    if (!fixture.active) {
        return __real_netdev_get_flags(dev, flags);
    }
    *flags = fixture.devices[fixture_device(dev)].up ? NETDEV_UP : 0;
    return 0;
}

int
__wrap_netdev_get_etheraddr(const struct netdev *dev, struct eth_addr *mac)
{
    if (!fixture.active) {
        return __real_netdev_get_etheraddr(dev, mac);
    }
    fixture_device(dev);
    *mac = (struct eth_addr) ETH_ADDR_C(02, 00, 00, 00, 00, 01);
    return 0;
}

int
__wrap_netdev_get_addr_list(const struct netdev *dev, struct in6_addr **addrs,
                           struct in6_addr **masks, int *n)
{
    if (!fixture.active) {
        return __real_netdev_get_addr_list(dev, addrs, masks, n);
    }
    *n = fixture.devices[fixture_device(dev)].addressed ? 1 : 0;
    *addrs = *n ? xmalloc(sizeof **addrs) : NULL;
    *masks = *n ? xmalloc(sizeof **masks) : NULL;
    if (*n) {
        ovs_assert(ip46_parse("192.0.2.10", *addrs));
        ovs_assert(ip46_parse("255.255.255.255", *masks));
    }
    return 0;
}

int
__wrap_netdev_get_ifindex(const struct netdev *dev)
{
    return fixture.active ? fixture_device(dev) + 11
                          : __real_netdev_get_ifindex(dev);
}

void
__wrap_netdev_get_addrs_list_flush(void)
{
    if (!fixture.active) {
        __real_netdev_get_addrs_list_flush();
    } else {
        fixture.flushes++;
    }
}

int
__wrap_ne_nl_dump_neigh(uint8_t family, int32_t ifindex,
                        struct vector *neighbors)
{
    if (!fixture.active) {
        return __real_ne_nl_dump_neigh(family, ifindex, neighbors);
    }
    ovs_assert(family == AF_INET && ifindex >= 11 && ifindex <= 12);
    size_t i = ifindex - 11;
    fixture.devices[i].dumps++;
    if (fixture.devices[i].populated) {
        struct route_next_hop *nh;
        VECTOR_FOR_EACH_PTR (&fixture.next_hops, nh) {
            if (!strcmp(nh->ifname, i ? "uplink-b" : "uplink-a")) {
                struct ne_nl_received_neigh neighbor = {
                    .if_index = ifindex,
                    .family = AF_INET,
                    .addr = nh->addr,
                    .lladdr = ETH_ADDR_C(02, 00, 00, 00, 00, 02),
                    .state = NUD_PERMANENT,
                };
                vector_push(neighbors, &neighbor);
            }
        }
    }
    return fixture.devices[i].error;
}

int
__wrap_ne_nl_resolve_neigh(int32_t ifindex, const struct in6_addr *addr)
{
    if (!fixture.active) {
        return __real_ne_nl_resolve_neigh(ifindex, addr);
    }
    ovs_assert(ifindex >= 11 && ifindex <= 12);
    fixture.devices[ifindex - 11].resolves++;
    return 0;
}

void
__wrap_ovn_netlink_update_notifier(enum ovn_netlink_notifier_type type,
                                  bool enabled)
{
    if (!fixture.active) {
        __real_ovn_netlink_update_notifier(type, enabled);
    }
}

static void
fixture_init(size_t n)
{
    memset(&fixture, 0, sizeof fixture);
    fixture.active = true;
    fixture.now = 1000;
    uuid_generate(&fixture.chassis.header_.uuid);
    uuid_generate(&fixture.datapath.header_.uuid);
    fixture.datapath.tunnel_key = 1;
    fixture.next_hops = VECTOR_EMPTY_INITIALIZER(struct route_next_hop);
    static char *names[] = {"lrp-a", "lrp-b", "lrp-c"};
    static const char *ips[] = {"192.0.2.1", "192.0.2.2", "203.0.113.1"};
    for (size_t i = 0; i < ARRAY_SIZE(fixture.ports); i++) {
        struct sbrec_port_binding *pb = &fixture.ports[i];
        uuid_generate(&pb->header_.uuid);
        pb->logical_port = names[i];
        pb->datapath = &fixture.datapath;
        pb->chassis = &fixture.chassis;
        pb->type = "";
        fixture.macs[i] = "02:00:00:00:00:01";
        pb->mac = &fixture.macs[i];
        pb->n_mac = 1;
        smap_init(&pb->options);
        smap_add(&pb->options, "dynamic-routing-port-name", "uplink");
        if (i < n) {
            struct route_next_hop nh = {
                .logical_port = pb->logical_port,
                .datapath = &fixture.datapath,
            };
            ovs_strlcpy(nh.ifname, i == 2 ? "uplink-b" : "uplink-a",
                        sizeof nh.ifname);
            ovs_assert(ip46_parse(ips[i], &nh.addr));
            vector_push(&fixture.next_hops, &nh);
        }
    }
    for (size_t i = 0; i < ARRAY_SIZE(fixture.devices); i++) {
        fixture.devices[i].up = true;
        fixture.devices[i].addressed = true;
        fixture.devices[i].present = true;
        fixture.devices[i].populated = true;
    }
}

static void
fixture_destroy(struct route_neighbor_state *state)
{
    route_neighbor_destroy(state);
    for (size_t i = 0; i < ARRAY_SIZE(fixture.ports); i++) {
        smap_destroy(&fixture.ports[i].options);
    }
    vector_destroy(&fixture.next_hops);
    fixture.active = false;
}

static void
fixture_run(struct route_neighbor_state *state)
{
    struct mac_cache_data cache = {.thresholds = HMAP_INITIALIZER(
                                  &cache.thresholds)};
    /* Port lookups are scripted; the index is never dereferenced. */
    route_neighbor_run(state, NULL, &fixture.next_hops,
                       (struct ovsdb_idl_index *) &fixture, NULL, NULL,
                       &fixture.chassis, &cache, true);
    hmap_destroy(&cache.thresholds);
}

static void
check_idle(void)
{
    for (size_t i = 0; i < 7; i++) {
        fixture_init(1);
        struct route_neighbor_state *state = route_neighbor_create();
        struct route_next_hop *nh = vector_get_ptr(&fixture.next_hops, 0);
        switch (i) {
        case 0:
            fixture.macs[0] = "02:00:00:00:00:01 192.0.2.10/24";
            break;
        case 1:
            smap_remove(&fixture.ports[0].options,
                        "dynamic-routing-port-name");
            break;
        case 2:
            fixture.ports[0].chassis = NULL;
            break;
        default:
            ovs_assert(ip46_parse(i == 3 ? "0.0.0.0" :
                                  i == 4 ? "255.255.255.255" :
                                  i == 5 ? "224.0.0.1" : "127.0.0.1",
                                  &nh->addr));
        }
        fixture_run(state);
        ovs_assert(!fixture.flushes && !fixture.opens);
        ovs_assert(!fixture.devices[0].dumps);
        ovs_assert(!route_neighbor_wake(state));
        fixture.now += 1001;
        ovs_assert(!route_neighbor_wake(state));
        fixture_destroy(state);
    }
}

static void
check_recovery(void)
{
    for (size_t i = 0; i < 3; i++) {
        fixture_init(1);
        struct route_neighbor_state *state = route_neighbor_create();
        fixture.devices[0].addressed = i != 0;
        fixture.devices[0].up = i != 1;
        fixture.devices[0].present = i != 2;
        fixture_run(state);
        ovs_assert(!fixture.devices[0].dumps);
        ovs_assert(!route_neighbor_wake(state));
        fixture.now += 1001;
        ovs_assert(route_neighbor_wake(state));
        fixture.devices[0].addressed = true;
        fixture.devices[0].up = true;
        fixture.devices[0].present = true;
        fixture_run(state);
        ovs_assert(fixture.devices[0].dumps == 1);
        ovs_assert(!fixture.devices[0].resolves);
        fixture_destroy(state);
    }
}

static void
check_snapshots(void)
{
    fixture_init(3);
    struct route_neighbor_state *state = route_neighbor_create();
    fixture_run(state);
    ovs_assert(fixture.devices[0].dumps == 1);
    ovs_assert(fixture.devices[1].dumps == 1);
    ovs_assert(!fixture.devices[0].resolves && !fixture.devices[1].resolves);

    /* Failed observations are neither absence nor a reason to repeat the
     * same dump for another next hop.  A different interface still works. */
    fixture.now += 1000;
    fixture.devices[0].error = EIO;
    for (size_t i = 0; i < ARRAY_SIZE(fixture.devices); i++) {
        fixture.devices[i].populated = false;
        fixture.devices[i].dumps = 0;
    }
    fixture_run(state);
    ovs_assert(fixture.devices[0].dumps == 1);
    ovs_assert(fixture.devices[1].dumps == 1);
    ovs_assert(!fixture.devices[0].resolves);
    ovs_assert(fixture.devices[1].resolves == 1);

    /* Neither successful nor failed snapshots survive a reconciliation. */
    fixture.now += 1100;
    fixture.devices[0].error = 0;
    fixture.devices[0].dumps = fixture.devices[1].dumps = 0;
    fixture.devices[1].resolves = 0;
    fixture_run(state);
    ovs_assert(fixture.devices[0].dumps == 1);
    ovs_assert(fixture.devices[1].dumps == 1);
    ovs_assert(fixture.devices[0].resolves == 2);
    ovs_assert(fixture.devices[1].resolves == 1);
    fixture_destroy(state);
}

static void
test_route_neighbor(int argc, char *argv[])
{
    ovs_assert(argc == 2);
    if (!strcmp(argv[1], "idle")) {
        check_idle();
    } else if (!strcmp(argv[1], "recovery")) {
        check_recovery();
    } else {
        ovs_assert(!strcmp(argv[1], "snapshots"));
        check_snapshots();
    }
}

OVSTEST_REGISTER("test-route-neighbor", test_route_neighbor);
