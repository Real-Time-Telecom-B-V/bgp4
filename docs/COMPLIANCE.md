# Standards compliance

What `bgp4` implements, per RFC. A row is marked **Done** only when the
behaviour is covered by tests that do not rely on this crate decoding its own
output: encoders are checked with Wireshark's dissector, decoders with bytes
produced by other BGP implementations.

Status values: **Done**, **Partial** (see notes), **Planned**, **Not planned**.

## Planned for the first release

| RFC | Title | Status | Notes |
| --- | --- | --- | --- |
| [4271](https://www.rfc-editor.org/rfc/rfc4271) | A Border Gateway Protocol 4 (BGP-4) | Partial | Codec for all four message types. State machine and decision process to come |
| [5492](https://www.rfc-editor.org/rfc/rfc5492) | Capabilities Advertisement with BGP-4 | Partial | Capabilities in the OPEN codec; negotiation belongs to the session, to come |
| [6793](https://www.rfc-editor.org/rfc/rfc6793) | BGP Support for Four-Octet Autonomous System (AS) Number Space | Partial | Codec complete: capability, AS_TRANS, AS4_PATH, AS4_AGGREGATOR. Negotiation belongs to the session |
| [4760](https://www.rfc-editor.org/rfc/rfc4760) | Multiprotocol Extensions for BGP-4 | Partial | Capability and the IPv6 unicast codec; negotiation belongs to the session, to come |
| [5065](https://www.rfc-editor.org/rfc/rfc5065) | Autonomous System Confederations for BGP | Partial | Confederation segments in AS_PATH, rejected from external peers. Session behaviour to come |
| [7705](https://www.rfc-editor.org/rfc/rfc7705) | Autonomous System Migration Mechanisms and Their Effects on the BGP AS_PATH Attribute | Planned | Per-session local AS, no-prepend, replace-AS |
| [7606](https://www.rfc-editor.org/rfc/rfc7606) | Revised Error Handling for BGP UPDATE Messages | Partial | Every attribute the crate interprets. Acting on the outcome belongs to the session and the RIB |
| [6286](https://www.rfc-editor.org/rfc/rfc6286) | Autonomous-System-Wide Unique BGP Identifier for BGP-4 | Partial | Zero identifier rejected in the codec; the AS-wide uniqueness rule belongs to the session |
| [6608](https://www.rfc-editor.org/rfc/rfc6608) | Subcodes for BGP Finite State Machine Error | Partial | Subcodes in the codec; the state machine that raises them is to come |
| [4486](https://www.rfc-editor.org/rfc/rfc4486) | Subcodes for BGP Cease Notification Message | Partial | Subcodes in the codec; sessions that send them are to come |
| [9003](https://www.rfc-editor.org/rfc/rfc9003) | Extended BGP Administrative Shutdown Communication | Partial | Encode and decode of the communication; sessions to come |
| [1997](https://www.rfc-editor.org/rfc/rfc1997) | BGP Communities Attribute | Partial | Attribute codec and well-known values. Honouring NO_EXPORT and NO_ADVERTISE belongs to policy, to come |
| [8092](https://www.rfc-editor.org/rfc/rfc8092) | BGP Large Communities Attribute | Partial | Attribute codec; matching in policy to come |
| [4360](https://www.rfc-editor.org/rfc/rfc4360) | BGP Extended Communities Attribute | Done | Carried, not interpreted |
| [8326](https://www.rfc-editor.org/rfc/rfc8326) | Graceful BGP Session Shutdown | Partial | Community value; the shutdown procedure belongs to the speaker, to come |
| [7999](https://www.rfc-editor.org/rfc/rfc7999) | BLACKHOLE Community | Partial | Community value; the origination bound belongs to policy, to come |
| [8212](https://www.rfc-editor.org/rfc/rfc8212) | Default External BGP (EBGP) Route Propagation Behavior without Policies | Planned | |
| [2385](https://www.rfc-editor.org/rfc/rfc2385) | Protection of BGP Sessions via the TCP MD5 Signature Option | Planned | Obsoleted by RFC 5925, still what most peers require |
| [5082](https://www.rfc-editor.org/rfc/rfc5082) | The Generalized TTL Security Mechanism (GTSM) | Planned | |

## Planned for later releases

| RFC | Title | Status | Notes |
| --- | --- | --- | --- |
| [2918](https://www.rfc-editor.org/rfc/rfc2918) | Route Refresh Capability for BGP-4 | Planned | |
| [4456](https://www.rfc-editor.org/rfc/rfc4456) | BGP Route Reflection: An Alternative to Full Mesh Internal BGP (IBGP) | Partial | ORIGINATOR_ID and CLUSTER_LIST codec. Loop checks to come; no built-in reflector |
| [9234](https://www.rfc-editor.org/rfc/rfc9234) | Route Leak Prevention and Detection Using Roles in UPDATE and OPEN Messages | Partial | Only-to-Customer attribute codec. Role capability and the leak checks to come |
| [4724](https://www.rfc-editor.org/rfc/rfc4724) | Graceful Restart Mechanism for BGP | Planned | |
| [8538](https://www.rfc-editor.org/rfc/rfc8538) | Notification Message Support for BGP Graceful Restart | Planned | |
| [5880](https://www.rfc-editor.org/rfc/rfc5880) | Bidirectional Forwarding Detection (BFD) | Planned | Asynchronous mode, no echo, no authentication |
| [5881](https://www.rfc-editor.org/rfc/rfc5881) | Bidirectional Forwarding Detection (BFD) for IPv4 and IPv6 (Single Hop) | Planned | |
| [5882](https://www.rfc-editor.org/rfc/rfc5882) | Generic Application of Bidirectional Forwarding Detection (BFD) | Planned | |

## Not committed

Candidates with no release assigned: TCP-AO
([5925](https://www.rfc-editor.org/rfc/rfc5925)), ADD-PATH
([7911](https://www.rfc-editor.org/rfc/rfc7911)), extended messages
([8654](https://www.rfc-editor.org/rfc/rfc8654)), extended optional parameters
length ([9072](https://www.rfc-editor.org/rfc/rfc9072)), IPv4 NLRI with an IPv6
next hop ([8950](https://www.rfc-editor.org/rfc/rfc8950)), enhanced route
refresh ([7313](https://www.rfc-editor.org/rfc/rfc7313)), Flowspec
([8955](https://www.rfc-editor.org/rfc/rfc8955)).

## Not planned

The crate is a customer-edge speaker, so the VPN and label address families
stay with the router: BGP/MPLS IP VPNs
([4364](https://www.rfc-editor.org/rfc/rfc4364)), EVPN
([7432](https://www.rfc-editor.org/rfc/rfc7432)), labeled unicast
([8277](https://www.rfc-editor.org/rfc/rfc8277)), constrained route
distribution ([4684](https://www.rfc-editor.org/rfc/rfc4684)), BGP-LS.
