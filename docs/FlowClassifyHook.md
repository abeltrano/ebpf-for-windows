
# EBPF for Windows Stream Inspection Hook


## Contents

1. [Purpose](#purpose)
2. [Requirements](#requirements)
3. [Alternative - Using existing Linux hooks](#alternative---using-existing-linux-hooks)
4. [eBPF Design](#ebpf-design)
    - [Program Type](#program-type)
    - [Attach Types](#attach-types)
    - [Hooks](#hooks)
5. [Architecture](#architecture)
    - [Hook Integration and Flow](#hook-integration-and-flow)
    - [Stream Hook Lifecycle](#stream-hook-lifecycle)
6. [WFP Implementation Details](#wfp-implementation-details)
7. [Datagram Extension](#datagram-extension)


---

## Purpose

Support an eBPF interface to support inspecting TCP stream data and then based on that allowing/blocking the connection.

The new hooks will support security and observability related solutions that require parsing TCP stream data
without incurring overhead for flows that can be ignored.

The [Datagram Extension](#datagram-extension) reuses the same program type with a separate attach
type for flow classification at `FWPM_LAYER_DATAGRAM_DATA_V4/V6`.

## Requirements

- Hook that allows choosing whether to classify a newly established TCP connection at the stream layer.
- Hook that receives each stream layer data segment in-order for both ingress and egress traffic.
  - 3 possible actions:
    - Allow the connection and stop being invoked for this flow.
    - Block the connection (no further invocations for this flow).
    - Allow the segment but keep getting invoked for further data segments (need more data to classify).
- Hook that supports cleanup of flows that were closed while still being classified.
- No eBPF programs should be invoked for segments on flows not needing stream layer classification.
- Multiple programs can be attached to the stream layer classify hooks at once.
  - Each program will be invoked in attached order until the flow is blocked or the program has allowed the flow.
- After a flow is allowed/blocked, there should be no further invocations of that program for the flow.
  - If the flow is blocked, no further stream-layer eBPF programs will be invoked for the flow.
  - If the flow is allowed, other stream layer programs that are still classifying the flow will continue to be invoked.
- We do not currently need any stream mutation support for these hooks -- only inline inspect/allow/block.
- Datagram-specific requirements are defined in the [Datagram Extension](#datagram-extension).

## Alternative - Using existing Linux hooks

Linux provides several eBPF program types, including:

- XDP: High-speed packet filtering and processing at the link layer.
- TC (Traffic Control): Packet shaping and filtering at the network and transport layers.
- SOCK_FILTER: Stream-layer filtering based on socket-level data, enabling payload inspection and application-specific processing.
- BPF_PROG_TYPE_SK_MSG: Socket-level filtering of outgoing messages being sent by attaching an SK_MSG program to an eBPF socket map.
- BPF_PROG_TYPE_SK_SKB: Socket parsing and filtering for incoming packets based on socket maps.
  - SK_SKB_STREAM_PARSER: L4 message parser for L7 protocol.
  - SK_SKB_STREAM_VERDICT: Pass/drop "messages" from stream.
  - SK_SKB_VERDICT: Pass/drop segments from TCP stream.

On Linux today, the required functionality can be implemented using the above program types with socket maps but there is no simple or well constrained way to support this.

- Requires multiple programs at multiple layers (and/or packet header parsing and TCP reassembly at a low network layer).
- There are no hooks for an eBPF program to classify _flows_ by inspecting _stream-layer_ data.
  - There are only hooks for classifying new flows and for classifying stream-layer messages.
  - Existing stream data classifying hooks only allow/drop individual packets/segments/messages.
  - Blocking connection requires injecting TCP RST, blocking individual packets/messages until timeout, or redirecting flows to a dummy socket.
- Most hooks only receive traffic in one direction.

## eBPF Design

The proposed stream inspection extension introduces a new eBPF program type for stream-layer flow classification, with three distinct hooks to enable fine-grained, stateful inspection and classification of TCP connections:

### Program Type

- **EBPF_PROGRAM_TYPE_FLOW_CLASSIFY**: A new program type for stream-layer flow classification. Programs of this type can be attached to one or more of the hooks described below.

_Note:_ Using a single program type for all 3 hooks enables tail calls between programs attached to the 3 hooks
to simplify flow classification designs.

The datagram extension reuses this program type.

```c
/**
 * @brief Action codes returned by flow classification programs.
 */
typedef enum _ebpf_flow_classify_action
{
    EBPF_FLOW_CLASSIFY_ALLOW,        ///< Allow the flow; no further stream inspection needed by this program.
    EBPF_FLOW_CLASSIFY_BLOCK,        ///< Block the flow; connection will be terminated.
    EBPF_FLOW_CLASSIFY_NEED_MORE_DATA,///< Allow current segment but continue inspection of subsequent segments.
} ebpf_flow_classify_action_t;

/**
 * @brief Flow direction indicators.
 *
 * For new flows (EBPF_FLOW_STATE_NEW), this indicates the connection direction
 * as determined by WFP at the flow established layer.
 * For established flows (EBPF_FLOW_STATE_ESTABLISHED), this indicates the
 * direction of the current data segment at the stream layer.
 */
typedef enum _ebpf_flow_direction
{
    EBPF_FLOW_DIRECTION_INBOUND,     ///< Inbound connection/segment direction.
    EBPF_FLOW_DIRECTION_OUTBOUND,    ///< Outbound connection/segment direction.
} ebpf_flow_direction_t;

/**
 * @brief Flow state indicators for classification context.
 */
typedef enum _ebpf_flow_state
{
    EBPF_FLOW_STATE_NEW,         ///< New flow being established; no stream data available yet.
    EBPF_FLOW_STATE_ESTABLISHED, ///< Established flow with stream data segment for inspection.
    EBPF_FLOW_STATE_DELETED,     ///< Flow deleted while still being classified; cleanup invocation.
} ebpf_flow_state_t;

/**
 * @brief Context structure passed to flow classification programs.
 *
 * Contains flow metadata and stream segment data for inspection.
 * Stream data pointers are only valid during program execution.
 */
typedef struct _ebpf_flow_classify
{
    uint32_t family; ///< IP address family.
    struct
    {
        union
        {
            uint32_t local_ip4;
            uint32_t local_ip6[4];
        }; ///< Local IP address.
        uint32_t local_port;
    }; ///< Local IP address and port stored in network byte order.
    struct
    {
        union
        {
            uint32_t remote_ip4;
            uint32_t remote_ip6[4];
        }; ///< Remote IP address.
        uint32_t remote_port;
    }; ///< Remote IP address and port stored in network byte order.
    uint8_t protocol;        ///< IP protocol.
    uint32_t compartment_id; ///< Network compartment Id.
    uint64_t interface_luid; ///< Interface LUID.
    uint8_t direction;       ///< 0 = inbound, 1 = outbound
    uint64_t flow_id;        ///< WFP flow handle
    uint32_t state;          ///< State of the flow.
    uint8_t* data_start;     ///< Pointer to start of stream segment data
    uint8_t* data_end;       ///< Pointer to end of stream segment data
} ebpf_flow_classify_t;
```

### Hook

1. **EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY**
   - **Invocation:** Called when new streams are established, for each TCP segment on flows that were classified as needing more data, and on flow deletion for unclassified flows.
   - **Purpose:** Allows the eBPF program to inspect stream data and allow/block the connection, or request more data if classification is not yet possible.
   - **Return values:**
     - `EBPF_FLOW_CLASSIFY_ALLOW`: The flow is permitted; the program requires no further stream inspection for this flow.
     - `EBPF_FLOW_CLASSIFY_BLOCK`: The flow is blocked; all further data is dropped (using WFP ABSORB), and the connection will be terminated or time out.
       - _Note_: WFP does not support blocking a flow at the flow-established layer, so if block is returned for
         a new flow the extension will remember the decision and block the flow on the first stream-layer WFP callout.
     - `EBPF_FLOW_CLASSIFY_NEED_MORE_DATA`: The current segment is allowed, but the program will be invoked again for subsequent segments until a final decision is made.
       - _Note_: If the flow is deleted before classification by an attached program, that program will be invoked
         one final time for cleanup (with the return value ignored).
   - **Notes:** This is only invoked for each flow segment until allow/block are returned (and only if NEED_MORE_DATA was returned when the flow was established).

```c
/*
 * @brief Handle flow classification (stream inspection).
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_FLOW_CLASSIFY
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_STREAM_FLOW_CLASSIFY
 *
 * Has different behavior based on ctx->state.
 *   EBPF_FLOW_STATE_NEW - Invoked when new flow is established.
 *     - ALLOW - No stream-layer classification of this flow needed by this program.
 *     - BLOCK - Block flow. No further program invocations for this flow.
 *     - NEED_MORE_DATA - Invoke this program for each stream segment until classification.
 *   EBPF_FLOW_STATE_ESTABLISHED - Invoked for each segment of established flows still needing classification.
 *     - ALLOW - Allow flow. No further invocations of this program for this flow.
 *       Other programs still classifying will get a final flow deleted invocation.
 *     - BLOCK - Block flow. No further invocations for this flow for this program.
 *     - NEED_MORE_DATA - Invoke this program for each stream segment until classification.
 *   EBPF_FLOW_STATE_DELETED - Invoked for each program that was still classifying the flow when it was deleted.
 *     - Return value ignored.
 *
 * @param[in] context \ref bpf_flow_classify_t
 * @retval FLOW_CLASSIFY_ALLOW The flow is permitted; no further stream inspection by this program for this flow.
 * @retval FLOW_CLASSIFY_BLOCK The flow is blocked; no further stream inspection for this flow.
 * @retval FLOW_CLASSIFY_NEED_MORE_DATA Allow current segment but continue inspection of subsequent segments.
 */
typedef flow_classify_action_t
stream_flow_classify_hook_t(bpf_flow_classify_t* context);
```

## Architecture

### Hook Integration and Flow

The extension uses the Windows Filtering Platform (WFP) to register callouts at both the flow established and stream layers.

1. When a new TCP flow is established, the extension initializes a per-flow context and invokes each program attached to the hook.
  a. Each program can return ALLOW/BLOCK/NEED_MORE_DATA to allow/block the new flow or classify the flow at the stream layer.

    b. If no stream-layer inspection is needed, the bpf program context is freed immediately.
    c. If any program returns `EBPF_FLOW_CLASSIFY_NEED_MORE_DATA`, the extension associates the context with the WFP stream layer callout to enable conditional callouts for this flow (using the WFP `CONDITIONAL_ON_FLOW` flag).
3. For each TCP segment, the extension invokes the `stream_flow_classify` hook, passing the current segment data and flow metadata. Each program can allow/block the flow or request more data as needed.

    a. If a program returns `FLOW_CLASSIFY_BLOCK` the context is freed and there will be no further invocations for this flow.

       - Programs that previously returned `NEED_MORE_DATA` will be invoked a final time for this flow with the `state` set to `EBPF_FLOW_STATE_DELETED`.

    b. If `FLOW_CLASSIFY_NEED_MORE_DATA` is returned, the current segment is allowed but the context is not freed.
4. If the flow is deleted while still in the NEED_MORE_DATA state (i.e., no final decision was made),
   each program that most recently returned NEED_MORE_DATA will be invoked a final time to notify them.

### Stream Hook Lifecycle

1. **Load and Attach**
    - The lifecycle begins with the setup of WFP filters. These filters are configured to be called at flow established for all TCP flows, and at the stream layer only for flows with the WFP context still set.
2. **Flow Established Callback and Invocation**
    - Extension initializes bpf program context and invokes the hook programs to decide whether to classify this flow at the stream layer.
    - Context is immediately freed if no classification is needed for this flow.
    - If classification is needed, the context is stored in the WFP stream layer callout context.
3. **Stream Callback and Invocation**
    - When stream data arrives, WFP triggers the extension through a callout. This callback serves as the starting point for stream-layer flow classification.
    - The stream layer callout is only invoked for flows still requiring invocation (using WFP CONDITIONAL_ON_FLOW).
4. **eBPF Program Invocation**
    - The extension invokes eBPF filter programs in the order they were attached.
    - On each invocation, the eBPF program will be presented with the data for the current segment.
    - Classify programs inspect the stream segment data and classify the connection using return codes:
        - **Allow**: The connection is deemed safe and permitted to proceed without further inspection by this program.
        - **Block**: Terminates the connection immediately.
        - **Need More Data**: Indicates the need for additional data for a conclusive decision. The extension allows the current segment and will invoke the program again for the next segment.
5. **Stream Inspection**
    - The eBPF program performs parsing/inspection tasks on the stream.
    - If the “Need More Data” return code is used, the inspection continues until a definitive decision is returned.
6. **Connection Termination or Continuation**
    - Once a decision other than "Need More Data" is reached (Allow or Block), the lifecycle for that connection ends within the context of the filter program.
    - For “Block,” the connection is terminated.
    - For “Allow,” the connection proceeds without further filtering.
    - If a connection is terminated while still being classified by a program, the program is invoked a final time with `EBPF_FLOW_STATE_DELETED`.

_Notes:_

- The [Windows Stream Inspection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/stream-inspection)
API is used for inspecting the stream-layer data via WFP callouts.
- The WFP `CONDITIONAL_ON_FLOW` flag means the stream-layer callout will only run for flows where the stream-layer WFP context (containing the bpf program context) is set.
  - The context is freed immediately if the flow is allowed at the flow established layer.
  - Otherwise the context is freed when an allow/block decision is made or the flow is deleted.
- When returning NEED_MORE_DATA, the current data segment is allowed (but the hook will keep getting invoked).
- Multiple eBPF programs can be invoked for a single stream.
  - If a program blocks the flow that decision is immediate and final.
  - If a program allows the flow, other programs returning NEED_MORE_DATA will continue to be invoked.
- No stream mutation is supported through these hooks (only inspection and allow/block).

### WFP Implementation Details

The stream inspection extension integrates with the Windows Filtering Platform (WFP)
at the flow_established layer to indicate flows for classification and at the stream layer to
classify flows.

Currently only inline stream classification will be supported.

#### WFP Action Mapping

The hook implementation maps eBPF program return values to specific WFP actions:

- **FLOW_CLASSIFY_ALLOW**: Returns `FWP_ACTION_PERMIT` and deletes the WFP flow context. This allows the current segment and terminates further classification for this flow by removing the flow context.

- **FLOW_CLASSIFY_BLOCK**: Returns `FWP_ACTION_BLOCK` with the `FWPS_CLASSIFY_OUT_FLAG_ABSORB` flag set. This blocks the current segment and terminates the connection by blocking all subsequent segments.

- **FLOW_CLASSIFY_NEED_MORE_DATA**: Returns `FWP_ACTION_PERMIT`. This allows the current segment to proceed while maintaining the flow context for continued classification of subsequent segments.
  - The initial stream-layer hook only supports passive inspection until an allow/block decision is made.
    - This avoids withholding data that higher level protocols need to proceed (which could stall/deadlock the flow).

#### Stream Inspection Model

The implementation supports **inline stream inspection only**, meaning:

- All classification decisions are made in the WFP callout.
  - No out-of-band or deferred processing is supported.
- Stream data is processed segment-by-segment as it arrives.
- No reassembly or reordering of TCP segments is performed by the hook (this is handled by the TCP stack before reaching the stream layer).
- Data is allowed through when `FLOW_CLASSIFY_NEED_MORE_DATA` is returned.
  - **Note**: The WFP `countBytesEnforced` field is not modified by these hooks,
    which currently only allow stream inspection and allow/block of flows.

#### Stream Data Handling

The hook provides direct access to stream segment data through the context's `data_start` and `data_end` pointers:

- **Contiguous Data**: When possible, pointers reference the original NET_BUFFER data directly for zero-copy access.
- **Non-contiguous Data**: For fragmented NET_BUFFERs, data is copied into a temporary buffer using `FwpsCopyStreamDataToBuffer0` to provide contiguous access to eBPF programs.
- **Data Lifetime**: Stream data pointers are only valid during the program invocation and must not be accessed after the program returns.

#### Resource Management

WFP resource management:

- **Conditional Callouts**: Stream layer callouts use the `FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW` flag to ensure they are only invoked for flows requiring classification.
- **Context Cleanup**: Flow contexts are immediately freed by the extension when the flow is allowed/blocked.
  For flows that terminate while still being classified, the extension will free them after invoking the program(s) in the flow deleted callout.
- **Memory Management**: Temporary buffers for non-contiguous data are allocated from non-paged pool and freed immediately after program execution.

## Datagram Extension

The datagram extension adds `EBPF_ATTACH_TYPE_DATAGRAM_FLOW_CLASSIFY` under
`EBPF_PROGRAM_TYPE_FLOW_CLASSIFY`. It does not change the STREAM attach type, lifecycle, or WFP
behavior described above.

### Datagram requirements

- The attach type covers the traffic delivered by `FWPM_LAYER_DATAGRAM_DATA_V4/V6`, including
  connected, unconnected, and raw-socket flows.
- Programs receive NEW, data, and DELETED callbacks for the WFP flow.
- Each data callback contains one complete, reassembled datagram payload with preserved boundaries.
- The context contains the current datagram tuple, direction, and stable WFP flow identifier.
- ALLOW stops callbacks for the returning program while other programs may continue.
- NEED_MORE_DATA permits the current datagram and continues classification of later datagrams.
- BLOCK drops the current and subsequent datagrams for the WFP flow until flow deletion or expiry.
  It does not promise that the underlying socket is closed.
- Process and application identity are not part of the FLOW_CLASSIFY context.

### Shared context

The shared context is extended with a data-path discriminator and protocol-metadata flags:

```c
typedef enum _ebpf_flow_classify_data_path
{
    EBPF_FLOW_CLASSIFY_DATA_PATH_STREAM,
    EBPF_FLOW_CLASSIFY_DATA_PATH_DATAGRAM,
} ebpf_flow_classify_data_path_t;

typedef enum _ebpf_flow_classify_metadata_flag
{
    EBPF_FLOW_CLASSIFY_METADATA_PORTS_VALID = 1 << 0,
    EBPF_FLOW_CLASSIFY_METADATA_ICMP_TYPE_CODE_VALID = 1 << 1,
} ebpf_flow_classify_metadata_flag_t;

// Fields appended to ebpf_flow_classify_t.
uint32_t data_path;      ///< ebpf_flow_classify_data_path_t.
uint32_t metadata_flags; ///< ebpf_flow_classify_metadata_flag_t bitmask.
```

`data_path` is set to `EBPF_FLOW_CLASSIFY_DATA_PATH_STREAM` or
`EBPF_FLOW_CLASSIFY_DATA_PATH_DATAGRAM` for every callback. Programs that can attach to both hook
types must check this field before interpreting `data_start` and `data_end`.

`metadata_flags` defines the interpretation of protocol-dependent fields:

- TCP STREAM and UDP DATAGRAM callbacks set `EBPF_FLOW_CLASSIFY_METADATA_PORTS_VALID`.
- ICMP and ICMPv6 DATAGRAM callbacks clear the port flag, set
  `EBPF_FLOW_CLASSIFY_METADATA_ICMP_TYPE_CODE_VALID`, and place type and code in `local_port` and
  `remote_port`.
- Raw or unrecognized protocols clear both flags.

For STREAM callbacks, `data_start` and `data_end` contain ordered TCP stream bytes. DATAGRAM
callbacks use these protocol-specific payload ranges:

- UDP and other recognized port-bearing transports: bytes after the transport header.
- ICMP and ICMPv6: bytes after the base ICMP header.
- Raw and unrecognized protocols: bytes after the IP header.

NEW and DELETED callbacks do not contain payload.

### Datagram lifecycle

The DATAGRAM attach provider registers callouts at
`FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4/V6` and `FWPM_LAYER_DATAGRAM_DATA_V4/V6`.

1. At FLOW_ESTABLISHED, invoke attached DATAGRAM programs with `state` set to
   `EBPF_FLOW_STATE_NEW`.
2. ALLOW removes the returning program. NEED_MORE_DATA keeps it active. BLOCK records blocked state.
3. If at least one program remains active or the flow is blocked, associate the context with the
   DATAGRAM_DATA callout using `FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW`.
4. For each datagram, populate the tuple and direction from the current datagram and invoke active
   programs in attachment order.
5. If no program remains active, disassociate and release the flow context.
6. If a program returns BLOCK, block the current datagram, invoke DELETED once for programs that
   were still active, release program state, and retain a minimal blocked-flow marker.
7. The blocked-flow marker drops later datagrams without invoking eBPF programs and is released at
   flow deletion or expiry.
8. A flow-delete callback invokes DELETED once for programs that are still active, then releases
   the context. Programs already cleaned up after BLOCK are not invoked again.

Public WFP documentation indicates that first inbound and outbound non-TCP packets for a unique
remote tuple pass through AUTH_RECV_ACCEPT or AUTH_CONNECT and FLOW_ESTABLISHED before
DATAGRAM_DATA. The implementation must validate connectionless-flow granularity, callback ordering,
and complete-datagram delivery on every supported Windows release, including wildcard-bound and
unconnected sockets. Programs that require peer- or transaction-specific state must use the current
tuple and protocol identifiers in addition to `flow_id` when needed.

### Datagram data handling

At DATAGRAM_DATA, `layerData` is a `NET_BUFFER_LIST`. Inbound and outbound data offsets differ.
The provider must normalize both directions to the payload ranges defined above and expose a
contiguous `data_start` to `data_end` range. Non-contiguous data is copied into temporary non-paged
storage and released after program execution.

The hook contract requires one complete, reassembled datagram per callback. The implementation must
validate this WFP behavior on every supported release. Partial fragments must not be exposed as
ordinary DATAGRAM callbacks.

### Validation

- Connected and unconnected UDP over IPv4 and IPv6, inbound and outbound.
- ICMP, ICMPv6, raw-socket, and other DATAGRAM_DATA traffic.
- FLOW_ESTABLISHED, DATAGRAM_DATA, and flow-delete ordering for unique remote tuples and
  wildcard-bound sockets.
- Inbound and outbound payload normalization and non-contiguous NBL handling.
- Complete-datagram delivery and fragment handling.
- Multiple attached programs and ALLOW, NEED_MORE_DATA, BLOCK, and exactly-once DELETED behavior.
- Persistent BLOCK until flow deletion or expiry.
- Active-flow, blocked-flow, and temporary-buffer resource limits.
- Program-info and verifier coverage for the shared context and both attach types.

### Non-goals

- Async PEND/complete. That behavior belongs to the separate
  [eBPF asynchronous processing proposal](https://github.com/microsoft/ebpf-for-windows/pull/5189).
- Independent one-datagram filtering semantics.
- Payload mutation, redirect, or rewriting.
- Process, application, or security-token identity propagation.
- Raw IP or transport-header exposure through the primary payload range.
- IP fragment reassembly in eBPF programs.

### References

- [Filtering layer identifiers](https://learn.microsoft.com/windows/win32/fwp/management-filtering-layer-identifiers-)
- [ALE layers](https://learn.microsoft.com/windows/win32/fwp/ale-layers)
- [UDP packet flows](https://learn.microsoft.com/windows/win32/fwp/udp-packet-flows)
