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
#include "openvswitch/compiler.h"
#include "route-neighbor.h"

struct route_neighbor_state *
route_neighbor_create(void)
{
    return NULL;
}

void
route_neighbor_destroy(struct route_neighbor_state *state OVS_UNUSED)
{
}

bool
route_neighbor_wake(struct route_neighbor_state *state OVS_UNUSED)
{
    return false;
}

void
route_neighbor_wait(struct route_neighbor_state *state OVS_UNUSED)
{
}

bool
route_neighbor_owns_binding(struct route_neighbor_state *state OVS_UNUSED,
                            const struct sbrec_mac_binding *mb OVS_UNUSED)
{
    return false;
}

bool
route_neighbor_observe(struct route_neighbor_state *state OVS_UNUSED,
                       const struct sbrec_port_binding *pb OVS_UNUSED,
                       const struct in6_addr *ip OVS_UNUSED,
                       struct eth_addr mac OVS_UNUSED,
                       long long observed OVS_UNUSED)
{
    return false;
}

void
route_neighbor_run(struct route_neighbor_state *state OVS_UNUSED,
                   struct ovsdb_idl_txn *txn OVS_UNUSED,
                   struct vector *next_hops OVS_UNUSED,
                   struct ovsdb_idl_index *pb_by_name OVS_UNUSED,
                   struct ovsdb_idl_index *mb_by_lport_ip OVS_UNUSED,
                   const struct sbrec_mac_binding_table *table OVS_UNUSED,
                   const struct sbrec_chassis *chassis OVS_UNUSED,
                   struct mac_cache_data *cache OVS_UNUSED,
                   bool ready OVS_UNUSED)
{
}
