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

#ifndef ROUTE_NEIGHBOR_H
#define ROUTE_NEIGHBOR_H 1

#include <stdbool.h>
#include <netinet/in.h>
#include "openvswitch/types.h"

struct route_neighbor_state;
struct mac_cache_data;
struct ovsdb_idl_index;
struct ovsdb_idl_txn;
struct sbrec_chassis;
struct sbrec_port_binding;
struct sbrec_mac_binding_table;
struct sbrec_mac_binding;
struct vector;

/* All functions run on ovn-controller's main thread. */
struct route_neighbor_state *route_neighbor_create(void);
void route_neighbor_destroy(struct route_neighbor_state *);
void route_neighbor_run(struct route_neighbor_state *,
                        struct ovsdb_idl_txn *, struct vector *next_hops,
                        struct ovsdb_idl_index *pb_by_name,
                        struct ovsdb_idl_index *mb_by_lport_ip,
                        const struct sbrec_mac_binding_table *,
                        const struct sbrec_chassis *,
                        struct mac_cache_data *, bool ready);
bool route_neighbor_wake(struct route_neighbor_state *);
void route_neighbor_wait(struct route_neighbor_state *);
bool route_neighbor_owns_binding(struct route_neighbor_state *,
                                 const struct sbrec_mac_binding *);

/* A managed-key observation requests kernel revalidation instead of allowing
 * another producer to write the same dynamic binding. */
bool route_neighbor_observe(struct route_neighbor_state *,
                            const struct sbrec_port_binding *,
                            const struct in6_addr *, struct eth_addr,
                            long long observed_msec);

#endif /* ROUTE_NEIGHBOR_H */
