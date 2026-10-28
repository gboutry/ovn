..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

===========================================
Next-hop MAC resolution implementation plan
===========================================

Status and intended behavior
----------------------------

This is a proposed implementation, based on main commit
``1c8d7419a73743f79ff54102c6b66f6c8061b756``. It does not describe an
implemented or tested feature. It supersedes the proposed Neutron-side
static-MAC reconciler as the preferred development direction.

Keep resolution inside OVN. ``ovn-northd`` will learn valid announcements
for route next hops outside an LRP's subnet coverage. ``ovn-controller``
will resolve and maintain eligible addressless-uplink next hops through the
Linux neighbor subsystem and publish ordinary SB ``MAC_Binding`` records.
This supplies both initial resolution and continued refresh, including
fabrics that do not answer OVN's zero-source ARP probes as expected.

The routing daemon remains external. In the intended deployment MicroOVN
manages BIRD, the host networking owner provisions numbered interfaces and
adjacent-peer reachability, and Neutron retains its generated topology.
Neither Neutron nor MicroOVN needs a neighbor reconciler, additional NB
write access, or an authoritative ``Static_MAC_Binding`` journal.

The algorithm uses interface identity and resolved next hops, not a special
case for an uplink prefix length. A host-route peer still needs explicit
Linux on-link reachability; a numbered point-to-point subnet needs its
ordinary connected route. Both endpoints must support the chosen numbering.

Implementation boundaries
-------------------------

* Do not number Neutron's fabric LRP, borrow the host IP under a different
  LRP MAC, allocate another underlay IP, or rewrite incoming ARP opcodes.
* Do not add an OVN routing daemon, external command dependency, background
  thread, NB journal, or schema column. Use the existing controller engine,
  poll loop, netlink utilities, IDL transactions and dynamic-MAC pipeline.
* Preserve IPv6 resolution, EVPN neighbor exchange, static-binding priority,
  route filtering and route withdrawal behavior. Kernel neighbor failure is
  not BGP/BFD failure detection or a substitute for route withdrawal.
* The complete host-backed resolver is Linux-specific and initially covers
  directly attached IPv4 next hops on mapped, IPv4-addressless LRPs. Keep
  non-Linux builds working through the existing netlink/stub organization.
* An addressless static IPv4 route is not already equivalent to a learned
  route: ``find_static_route_outport()`` currently rejects a NULL IPv4 source
  even with an explicit output port. Do not change that parser in this
  series. Generate learning flows for successfully parsed routes regardless
  of origin; treat broader static-route support as a separate proposal.

Observed gaps and existing building blocks
------------------------------------------

``build_neigh_learning_flows_for_lrouter_port()`` in ``northd/northd.c``
builds ARP-request learning flows by iterating the LRP's IPv4 networks.
An addressless LRP has none. The bug reporter observed a GARP request reach
that LRP and miss learning, while an ARP reply learns successfully. This is
an observed interoperability failure; the plan does not depend on a blanket
claim about which vendor behavior RFC 5227 requires.

``mac_binding_probe_stats_run()`` in ``controller/mac-cache.c`` selects an
IPv4 probe source from an LRP network containing the neighbor. It cannot
refresh this addressless case. Learning GARP alone therefore cannot prove
cold-cache resolution, silent MAC replacement or continued reachability.

Reuse the following implementation points:

* ``build_route_data_flows_for_lrouter()`` walks unique and ECMP routes.
  Its grouped-route ``lflow_ref`` is rebuilt by the existing incremental
  handler in ``northd/en-lflow.c``.
* ``sb_sync_learned_routes()`` and ``route_table_resolve_and_sync()`` in
  ``controller/route-exchange.c`` already associate a resolved kernel
  next hop with an eligible logical port and interface. Expose that result
  rather than independently interpreting routing tables again.
* ``controller/neighbor-exchange-netlink.c`` provides ``ne_table_parse()``,
  neighbor records and dump construction. Its existing EVPN synchronization
  also installs/removes Linux neighbors; it must not be called on uplinks.
* ``controller/ovn-netlink-notifier.c`` already receives neighbor changes.
  Neighbor-watch replacement and event flushing are currently shared state,
  so two consumers need unioned watches and explicit event fan-out.
* ``mac_binding_add_to_sb()`` in ``lib/mac-binding-index.c`` supplies the
  ordinary dynamic binding writer. The EVPN MAC-sync engine node provides
  examples of pending-SB-write handling, persisted row UUIDs and timers.
* ``controller/neighbor.c`` advertises neighbors for EVPN, and
  ``controller/neighbor-of.c`` implements binding flow priorities. Neither
  supplies this uplink resolver. Preserve their existing responsibilities.

Northd correction
-----------------

Add a small route-next-hop learning helper, called from
``build_route_data_flows_for_lrouter()`` for unique routes and every ECMP
member. Deduplicate ``(output LRP, IPv4 next hop)`` while processing a
datapath. Generate a rule only if existing subnet-based learning does not
already cover the next hop. Require a successfully parsed route, explicit
resolved output LRP and valid unicast next-hop address.

Match the narrow announcement case::

    inport == P && arp.op == 1 && arp.spa == N && arp.tpa == N

Use the existing lookup/learn-neighbor pipeline and meters. Factor its
lookup-action construction if necessary; do not add a parallel learning
table. Preserve sender validation and the existing distributed-gateway
``is_chassis_resident()`` condition.

Preserve ``always_learn_from_arp_request=false``: use the existing
``lookup_arp_ip()`` action and unknown-sender suppression. A route does not
silently override that administrator setting. With that option false, the
controller resolver supplies initial state independently, and an already
known IP can be updated by ordinary native learning where applicable.

Attach rules to ``route_node->lflow_ref``, not only a port reference. Test
next-hop replacement, shared next hops, last-route withdrawal, ECMP removal,
LRP recreation and address/option changes against a full recomputation.
No new persistent northd reference-counting subsystem is needed.

Controller resolver
-------------------

Add ``controller/route-neighbor.c`` and ``.h`` for desired next-hop state,
bounded resolution and SB publication. Register them in
``controller/automake.mk``; use the existing ``HAVE_NETLINK`` structure and
stub pattern for platform-specific functions. Keep general key/state helpers
independent of Linux message encoding where practical.

Eligibility and automatic activation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use existing explicit dynamic-routing interface configuration as the scope;
do not add another table-ID or peer configuration option. The resolver is
automatic only when all these conditions hold:

#. The local route-exchange path accepted an IPv4 route and resolved its
   next-hop interface using the existing protocol/route filters.
#. The output LRP has no IPv4 addresses, permits route learning, and has a
   ``dynamic-routing-port-name`` resolving through the local port mapping
   to that exact Linux interface. An unspecified interface is insufficient.
#. The controller is the actual active chassis for the LRP, including a
   distributed gateway's chassisredirect binding where applicable. Merely
   belonging to its HA group or having its datapath locally is insufficient.
#. The current interface exists, supports Ethernet ARP, is operational and
   has a usable host IPv4 address and direct peer reachability. Do not infer
   adjacency solely from the local subnet mask, or recursively resolve via
   an unrelated default gateway.

An unsupported mapping or interface produces a rate-limited diagnostic and
does not silently broaden scope. Ports outside this set retain their native
behavior. Record this automatic behavior change in NEWS and document its
trust assumptions. Do not advertise this first version as arbitrary
multi-hop, DPDK-only or separate-network-namespace support.

Represent a managed key using datapath/PB UUIDs, IPv4 next hop, interface
index and interface incarnation. Include the route table and mapping in
the generation context. Reference count the union of accepted routes, so
one route withdrawal cannot remove a still-used next hop. Identical peer
addresses on separate interfaces or logical routers remain separate keys.

Engine and notifier integration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Expose the candidate set from route exchange after its existing interface
and ``dynamic-routing-no-learning`` filtering, for both full and incremental
route updates. Add a route-neighbor ``SB_WRITE`` engine node using that set,
shared neighbor/link notifications, PB/residency changes, SB MAC bindings,
SB writeability, conditional-monitor completion and a retry/refresh waker.
Ensure its dependencies order route import and neighbor publication into
the same current transaction where possible; do not require a committed
``Learned_Route`` round trip to discover a newly accepted kernel route.

Extend neighbor notifier plumbing so EVPN and route-neighbor consumers
contribute separate watch sets. The notifier subscribes to their union and
copies a batch/loss indication to both consumers before flushing it. Neither
consumer may replace the other's watches or consume events exclusively.
Apply the same rule to shared interface watches. Use current poll-loop
``run``/``wait`` patterns and engine wakers, not a new reader thread.

Subscribe before the initial dump. Extract an error-reporting, read-only
neighbor dump API from the existing dump code and propagate
``nl_dump_done()`` status. Build a temporary snapshot, then apply queued
notifications before publishing it. On event loss or interrupted dumps,
discard the partial snapshot and rescan. Do not interpret an incomplete
view as absence or delete Linux state while reading it.

Kernel solicitation and freshness
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add narrow resolution helpers beside the neighbor machinery:

* For a missing dynamic neighbor, request kernel use with
  ``RTM_NEWNEIGH``, ``NLM_F_CREATE`` and ``NTF_USE``, specifying the IPv4
  destination and interface and supplying no MAC. This asks Linux to resolve
  the neighbor using its host interface identity. For a missing entry, use
  exclusive creation and reread on ``EEXIST`` rather than changing an entry
  that appeared after the snapshot.
* ``NTF_USE`` is not a forced refresh of an already reachable entry. For an
  existing dynamic entry, send a normal ARP request using the host interface's
  actual MAC and IPv4 address, without a state-changing neighbor update.
  Reuse packet composition and transmission facilities already used by
  ``send_self_originated_neigh_packet()`` in pinctrl where their egress path
  fits the mapped interface; use the existing netdev send API otherwise.
  The system test must prove the request exits the intended host uplink and
  its response reaches Linux. A failed existing entry follows this same
  request path; if it disappears, retry exclusive creation.
* Do not probe ``PERMANENT`` or ``NOARP`` entries. Accept a valid explicitly
  configured permanent neighbor as administrative state. Exclude
  EVPN/OVN-exported neighbors to prevent
  importing the controller's own advertisements as fabric observations.

A preflight read is not an atomic guard against an administrator changing
an existing entry to permanent. In particular, do not use a ``NUD_PROBE``
state rewrite as a shortcut: administrative netlink updates lack the needed
compare-and-set guard. Ordinary ARP reception retains the kernel's handling
of permanent entries. Race requests against administrative replacement in
the system test and verify both the permanent MAC and its state survive.

Validate the current interface identity, host address and adjacency before
each request. In particular, prove source selection for off-prefix host
routes and VRF-slaved interfaces. Kernel behavior is an implementation gate:
source inspection or acknowledgment of a netlink request is not proof that
the expected ARP packet was emitted or that a neighbor was confirmed.

Publish a new dynamic binding from a confirmed ``REACHABLE`` neighbor with
a valid unicast MAC, or from valid administrative ``PERMANENT`` state.
``STALE``, ``DELAY`` and ``PROBE`` can retain an existing usable binding
during normal revalidation but cannot seed a new binding or renew its SB
timestamp indefinitely. Missing, ``INCOMPLETE`` and ``FAILED`` state cannot
confirm a binding. A fresh snapshot of the same unconfirmed entry is not
new reachability evidence.

Track a per-key revalidation epoch separately from topology generation.
A contradictory announcement advances that epoch, invalidating older
snapshots, confirmations and queued timestamp renewals. A probe result can
confirm only its current epoch. Track confirmation after each forced refresh.
Do not refresh the timestamp from the pre-probe reachable snapshot when an
announcement triggered revalidation. Retry with bounded exponential backoff;
start at
one second and cap at 30 seconds per interface/next-hop. Coalesce references
and limit per-iteration work. Use a named 30-second repair-scan interval and
integrate refresh scheduling with the existing MAC-aging threshold/waker,
so smaller configured aging thresholds do not simply wait for that scan.
Measure supported timing in tests rather than claiming a fixed outage bound.

Extend the parsed neighbor record with ``NDA_CACHEINFO`` confirmation age
where available. A successful same-MAC ARP confirmation need not produce an
observable state-change event; a follow-up dump must distinguish genuinely
new confirmation from rereading an old ``REACHABLE`` value. Normalize kernel
time units through existing time helpers, test their precision/wrap handling,
and do not infer new confirmation when cache information is unavailable.

Dynamic-cache authority and native learning
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For currently managed keys, make kernel resolution the single publication
authority. Reuse ``mac_binding_add_to_sb()`` and ordinary dynamic priority;
do not create NB/SB static bindings or bypass operator static precedence.
On takeover of an eligible local key, reconcile its existing dynamic row
against fresh kernel state, including invalidating an unresolved stale value
before relying on it for newly imported traffic.

Add a small main-thread managed-key check to
``pinctrl.c:run_put_mac_binding()``. A valid packet observation for a managed
key becomes a nonblocking revalidation hint, not a competing SB update or a
request to install the packet's claimed MAC in Linux. Check management and
residency at write time, covering packets already in the pinctrl ring and
buffer. Unmanaged keys retain the existing writer behavior.

Likewise, route managed-key refresh requests from
``mac_binding_probe_stats_run()`` to the resolver. Leave ordinary native
probing untouched for other keys. Neither pinctrl nor mac-cache performs a
blocking dump or netlink transaction from a packet-handler thread. This
removes competing managed-key SB writers and fences queued stale work.
An SB transaction already submitted before a later kernel event cannot be
atomically canceled against that event; subsequent fresh reconciliation must
repair it. The guarantee is convergence after that race, not the absence of
every transient stale value.

Keep runtime records of committed binding UUID, MAC, datapath and timestamp,
plus the scope generation. A queued transaction is tentative; confirm its
result through the IDL/commit outcome before recording ownership. Pending
work survives unavailable transactions and is rederived after reconnect.
Before destructive changes, verify the current row, generation and active
residency. A changed/replaced row outside current authority must be left
alone. Do not copy EVPN's tracked-UUID deletion without these guards.

Route withdrawal or local interface removal stops references and removes
only an unchanged runtime-recorded binding while local authority still
holds. A neighbor failure invalidates a dynamic binding inside the current
managed scope; it does not delete static overrides or withdraw a route.
Existing dataplane flows can persist during DB outages and propagation, so
this is not a promise of immediate fail-closed forwarding.

On residency loss, stop publishing and discard pending intents; do not
delete the shared binding after a new chassis becomes owner. The new active
chassis derives its own managed scope and reconciles from its kernel.
Verify PB/chassis columns in the SB transaction so a transaction based on
superseded residency retries instead of committing silently.

After restart, current eligible keys are reconstructed without a journal.
Unreferenced old dynamic cache rows have no reconstructible importer
provenance: leave them to normal configured aging and existing northd
port/datapath cleanup. With aging disabled they may remain, as other native
dynamic cache entries can. Do not claim exhaustive orphan deletion. Stale
bindings must be reconciled before an eligible key becomes useful again.

Lifecycle checklist
-------------------

* Startup: honor complete SB conditional-monitor loading and the route
  exchange readiness guards before destructive reconciliation. Then dump
  neighbors and derive scope; support routes, interfaces and neighbors
  appearing in any order.
* Steady state: handle route/ECMP changes, neighbor confirmation/failure,
  MAC replacement, host address changes and link state. Sharing a gateway
  across prefixes must not multiply probes or SB writes.
* Reconfiguration: rebuild generation on mapping/table/interface/PB changes,
  distinguish an interface recreated with the same index, and handle a port
  gaining an IPv4 address by leaving the managed scope conservatively.
* Event loss: repair after notifier overflow, invalid messages, dump failure
  and lost interface events. A bad snapshot suspends destructive repair for
  that scope; a complete snapshot proving removal permits guarded cleanup.
* Database outage: retain pending desired work, use the existing SB read-only
  retry path, and resnapshot before writes after reconnect/leader change.
  Never turn a missing transaction or partial IDL into an empty desired set.
* HA: standby route preparation is not permission to publish shared MACs.
  Fence previous-owner pending writes and cleanup; test with different
  next-hop MACs on the two chassis.
* Shutdown: use existing engine cleanup, notifier teardown and route-exchange
  destruction. Stop timers and release maps/sockets. Retain committed dynamic
  cache state across an ordinary restart; do not add a new shutdown framework
  or remove host addresses, routes or administrative neighbors.

Trust and compatibility
-----------------------

Only actual route next hops on explicitly mapped local uplinks are eligible.
Reject arbitrary neighbors, wrong-interface observations, invalid MACs,
multicast/zero/local/broadcast next-hop addresses and nonlocal bindings.
Recognize valid point-to-point endpoints rather than treating their highest
address as a broadcast. Route-scoped GARP permissions disappear with their
last route reference. ARP trust on the physical fabric is unchanged; these
checks are scope controls, not authentication against a malicious ToR.

No database schema or new logical action is planned. Follow existing
column-availability checks for MAC timestamps during rolling upgrades.
Native GARP learning can help with an older controller; an older controller
does not gain the host-backed resolver merely by upgrading northd. Test
mixed versions and state the required component versions together.

Tests and evidence
------------------

Northd and simulated dataplane
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Extend ``tests/ovn-northd.at`` beside
``dynamic-routing - learned routes on unnumbered LRP`` and
``dynamic-routing incremental processing``. Cover exact-key flow generation,
wrong-port/IP exclusion, shared next hops, ECMP, learning-option toggles,
LRP/address changes, withdrawal and router recreation. Compare incremental
results with ``CHECK_NO_CHANGE_AFTER_RECOMPUTE`` and retain the existing
engine-stat assertions where applicable.

Extend ``tests/ovn.at`` beside ``MAC binding learning from ARP request and
ND NS``, ``IP relocation using GARP request`` and ``MAC binding aging -
probing``. Exercise real packet injection and SB/flow observations, both
values of ``always_learn_from_arp_request``, static-binding priority and
IPv6 regressions. Add a delayed buffered native-write test proving it cannot
overwrite a managed key after confirmation or ownership change.

Netlink and real-kernel system tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Extend ``tests/test-ovn-netlink.c`` and ``tests/system-ovn-netlink.at`` near
``sync netlink neighbors - learn IP neighbors`` and ``table notify``.
Test read-only dump behavior, errors and notification fan-out alongside
EVPN. Prove actual create/use and forced-probe behavior, packet source IP/MAC,
state transitions and permanent-neighbor preservation. An ACK-only test is
insufficient. Add invalid/truncated-message cases to the native parser
test harness rather than inventing a Python test runner.

Extend ``tests/system-ovn.at`` near ``dynamic-routing - route learning
filter port name`` and ``dynamic-routing - BGP learned routes``:

* Cold Linux and OVN caches on numbered uplinks, including a /32 with an
  off-prefix scope-link peer route, /31 endpoints and ordinary /30 hosts;
  root and supported VRF routing contexts; missing prerequisites diagnosed.
* Drop zero-source ARP in the peer fixture, answer normal kernel ARP, and
  verify traffic. Separately exercise announcement-only native learning and
  a peer that changes MAC without sending a GARP.
* Probe/refresh across aging thresholds; no timestamp renewal from stale
  state or dataplane use alone; failed resolution and recovery; changed MAC
  during an SB outage and resynchronization afterward.
* Route replacement, multiple prefixes sharing a next hop, multiple ECMP
  uplinks, identical IPs on different interfaces, interface deletion/index
  reuse, mapping/table changes and host address removal/re-addition.
* Controller restart, SB reconnect/read-only/leader transition, partial
  conditional monitors, notifier loss, interrupted dump and transaction
  failure. Separate mocked error-injection evidence from real clustered
  DB failover evidence if the standard fixture is standalone.
* HA active/standby transition with distinct kernel neighbors; stale old
  owner writes; simultaneous EVPN neighbor activity; static overrides and
  no deletion of administrative Linux state.

Use ``AT_SETUP``/``AT_KEYWORDS``, ``OVN_FOR_EACH_NORTHD``, ``ovn_start``,
``check``/``check_uuid``, namespace/VRF macros, packet helpers and
``OVS_WAIT_*``/``wait_row_count``. Use fixture cleanup hooks and no arbitrary
sleeps. Assign new cases the keyword ``next-hop-neighbor``; this is a planned
selector, not an existing test selection.

Native verification sequence
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Follow :doc:`/intro/install/general` to populate and build the pinned OVS
submodule, then bootstrap/configure OVN with ``--enable-Werror`` and the
documented OVS source/build paths. Run targeted tests for each patch and
the full native suite for the completed series::

    make check TESTSUITEFLAGS='-k dynamic-routing'
    make check TESTSUITEFLAGS='-k next-hop-neighbor'
    make check
    make check-kernel TESTSUITEFLAGS='-k next-hop-neighbor' SUDO='sudo -E'
    make check-system-userspace SUDO='sudo -E' \
        TESTSUITEFLAGS='-k next-hop-neighbor'
    make docs-check
    make distcheck

Also run existing shared netlink-neighbor and EVPN selections when changing
their notifier/dump paths. Compile the non-netlink stub configuration; run
available GCC/Clang and memory-check targets as documented for the change.
Kernel and userspace system suites must run serially in an isolated test
environment, not against an unrelated host OVS instance.

Native route-import tests do not establish BIRD integration. Final live
acceptance must use actual BIRD-generated routes with the proper protocol
marker, unchanged Neutron topology and the intended fabric. Capture host ARP
source identity, Linux neighbor states, SB learned routes/MAC bindings,
installed flows and bidirectional VM/FIP traffic. Include cold start,
withdrawal, silent MAC change, aging, restart and dual-uplink loss/recovery.
Report versions, counts, skips, measured convergence and untested boundaries.

Patch series and project conventions
------------------------------------

Prefer three independently buildable patches, with tests in each:

#. ``northd: Learn next-hop GARP on unnumbered ports.`` Narrow route-scoped
   learning and incremental-flow tests. This is a useful bug fix but must
   not be described as complete addressless neighbor resolution.
#. ``controller: Share read-only neighbor observations.`` Error-reporting
   read-only dumps, notifier watch union/fan-out and native regressions
   proving EVPN still receives its events. Add probe-helper tests here if
   that keeps the helper independently useful and reviewable.
#. ``controller: Resolve mapped uplink next-hop neighbors.`` Complete
   candidate/state engine, kernel solicitation/refresh, SB publication,
   pinctrl/mac-cache arbitration, HA/lifecycle handling, native/system tests,
   docs/manpage updates and NEWS. Do not split seeding from its necessary
   recovery and writer-fencing behavior merely to make patches smaller.

If the final feature patch becomes difficult to review, split a coherent,
tested helper prerequisite out first, without enabling a partial resolver.
Use the existing hmap/vector/IDL/poll-loop idioms, module prefixes, four-space
C indentation, 79-column source lines and RST documentation. Add any new
file to its Automake source list and documentation distribution list.

OVN submits email patches to ``dev@openvswitch.org`` with
``[PATCH ovn n/m]`` subjects, tracked through Patchwork; this is not a Gerrit
series. Identify the introducing commit before adding a ``Fixes:`` trailer,
reference LP #2165017 with the project's report-link convention, and do not
invent review/test acknowledgments. Follow the documented internal-version
rules if implementation ultimately adds or changes logical actions.

OVN's submission guide requires a DCO sign-off. The user's current
instructions prohibit adding that trailer, so local planning commits omit
it and are not submission-ready. Preserve the requested
``Assisted-By: Codex (kebab-model)`` attribution and 72-column body wrapping.
No mailing-list message, remote push, CI trigger or live deployment is part
of preparing this plan.

Current verification boundary
-----------------------------

The inspected checkout has no generated Makefile or configured build, and
its pinned OVS submodule is uninitialized. Runtime tests have not been run
for this plan, and no runtime implementation is included. A documentation
build cannot prove kernel solicitation, MAC convergence or traffic delivery.
Record documentation checks separately from the native and live acceptance
results when implementing the series.

References
----------

* `LP #2165017 <https://bugs.launchpad.net/neutron/+bug/2165017>`_.
* https://mail.openvswitch.org/pipermail/ovs-discuss/2026-September/054016.html
* `Linux v6.8 neighbor use handling
  <https://github.com/torvalds/linux/blob/v6.8/net/core/neighbour.c>`_.
* :doc:`/internals/contributing/submitting-patches`,
  :doc:`/internals/contributing/coding-style` and
  :doc:`/topics/test-development` define the project workflow used here.
