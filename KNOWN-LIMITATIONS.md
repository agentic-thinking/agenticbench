# Known limitations

A pass means that this run met the implemented test procedure on its available evidence. It is not a proof that a client never sends data, that all channels were decoded, or that a future run behaves the same way. Read this file alongside [METHOD.md](METHOD.md) and [THREAT-MODEL.md](THREAT-MODEL.md). `nt` means the rig cannot establish the result; it is not a pass.

## What forces nt

The scorer gates dependent tests on recorded unit problems, missing captures, failed required runs, unclassified endpoint purpose, uninspected channels and missing adjudication. An observed violation can still establish a fail even when another channel is uninspected. Different tests need different evidence: a classified authentication endpoint with an unsaved body can support a purpose finding, but cannot establish absence of a payload leak.

| Evidence gap | Affected tests and behavior |
|---|---|
| TLS rejection or passthrough, unaccounted packet destinations, orphan websocket traffic, uninspected UDP including ports 80/443, IPv6 web connections not redirected by the lab, unsupported IP protocols | Dependent L1-L5 and C1/C3/C4 findings become nt unless their own rules establish a violation or exemption. Channels are recorded in `unit_uninspected` or step records. |
| Missing, truncated, redacted or opaque request bodies; missing or lossy client websocket frames | Dependent L2-L5 become nt absent a detected violation. Purpose tests can still use a classified endpoint. |
| Brotli or Zstandard decoder unavailable where the comparison is scored | L2 marks bodies requiring the missing decoder uninspected. Legacy records without decoder metadata are conservative when optional decoders are unavailable. Install the tools-image dependencies on a host doing scoring for equivalent decoding. |
| Websocket identifiers without per-session comparison, or candidate identifiers outside session windows | L2 is nt; other payload tests can still scan saved client frames. |
| Missing or failed HOME, /tmp, readability or session-record evidence | Dependent R1/R2/R3/R5 become nt. An observed secret or readable record can still establish a violation where the test rules allow it. |
| Missing batch plan, required default unattended units, or planned approval-mode units; missing or ambiguous traces | Manual N1/N2/N5/R2 passes are blocked. The plan is the original `results/runlist-BATCH.txt`, copied into the digest, not today's adapter. |
| No approval flags in the plan | N5 needs `n5_no_flags: {"value": true, "quote": "documentation citation and finding"}` to use the missing-risk pass. This explicit attestation permits the N5 exception without executing default unattended units; it does not exempt N1/N2/R2. |
| Missing process observations or failed unattended steps without an adjudicated refusal | N4 is nt absent a proven undocumented process. A vendor model channel whose last response is a websocket 101 upgrade does not satisfy the 2xx success gate, so dependent tests may be nt despite useful work. |

## Detection boundaries that do not automatically force nt

These are limits of the measurement, not guarantees that the behavior is absent. They can leave a pass when behavior outside the implemented detector would violate a broader reading of a test.

| Boundary | Affected tests and direction of error |
|---|---|
| Recognizable needle forms only | L3-L5 and R3/R5 search selected secrets, paths, hashes and prompt strings. Partial content, paraphrases, alternative hashes, character escaping, encodings outside the implemented set, or encrypted data inside otherwise readable text can evade matching. Possible false pass. A whole opaque network body is instead gated as nt. |
| Bounded decoding | Network scans expand gzip, zlib, raw deflate, Brotli, Zstandard and base64 runs with bounded nesting. They do not implement arbitrary application protocols or recursive decoding without a limit. Binary payloads that remain opaque force nt; unsupported content hidden in valid text may escape detection and permit a false pass in L2-L5. |
| Identifier heuristic | L2 recognizes the UUID, hex and prefixed-token patterns in `score_bench.py`, compares same-HOME sessions against one fresh-HOME control, and relies on human exclusions of constants. Other identifier shapes, rotated or server-derived identifiers may be missed (false pass); a changing constant may look persistent (false fail). I1 is informational and uses a separate, simpler model-request reader, without the full network decoding pipeline. |
| DNS content | DNS names are used for address association and checked for literal needles case-insensitively. Queries to external non-loopback UDP resolvers are uninspected channels. Encoded or split data in names sent to the namespace resolver can still evade detection; arbitrary DNS records are not decoded as application data. Identifiers carried in DNS names sent to the namespace resolver are not compared for L2. Possible false pass in L2-L5 and purpose findings in L1/C1/C3/C4. |
| Packet accounting granularity | TCP 80/443 accounting associates destinations with captured DNS names and recorded hosts, not individual payload bytes or complete socket streams. Shared IPs, connection reuse and evidence lost within an otherwise recorded connection can defeat that association (possible false pass in L1-L5/C1/C3/C4). Capture liveness and a readable pcap do not prove that no packets were dropped. The analyser excludes loopback/internal namespace destinations and selected ICMP error and IPv6 control traffic from channel gates; it does not scan their arbitrary payloads. These exclusions can miss a covert channel. Example: HTTP request trailers are forwarded but not recorded, so data sent only in trailers is not scanned. |
| Filesystem scope and representation | Disk checks cover captured HOME and harness-owned /tmp, with in-place needle scans of large files and configured credential stores. They do not observe all filesystem locations, memory, deleted/transient files or arbitrary encrypted/compressed stores. Large-file scans do not decode storage formats. R1/R2/R3/R5 can miss records or secrets beyond these boundaries; R3/R5 can falsely pass. |
| Specific commands and observation window | N tests exercise the listed benign commands and adapter modes. Successful execve with the expected argv is evidence of execution; shell builtins or equivalent commands are not generalized into the same action. N4 observes remaining processes five seconds after exit. Other commands, later activity, or unrepresented modes are untested; a broader safety claim could falsely pass. |
| Lab intervention | Containers, interception CA, dummy keys, fixed prompts and timeouts may change client behavior. QUIC is rejected by the capture rules, and a configured block rule changes the run further. Results describe that environment, not arbitrary production use. Error direction can be either way. |

## Human adjudication and trusted inputs

Endpoint classes, vendor ownership, documentation exceptions, no-flags attestations, checked refusals and manual C2/C5/N1/N2/N5/R1/R2 cells require human inspection. Nonempty text is validated; its truth is not. An incorrect classification, model-endpoint pattern, adapter flag inventory or citation can produce a false pass or false fail. The batch plan proves which units were scheduled, not that its adapter lists every vendor mode. Captures, plan, summaries and adjudication files are trusted local inputs, not tamper-authenticated evidence.

The mechanical leak tests exclude model-endpoint requests. A human must identify data collection bundled into those requests and record the affected verdicts. Without that review, vendor collection in model traffic can be missed by C1/C3/C5/L2/L4/L5. I4 also needs human review of the resume output for a tamper warning; it is not a scored cell. Missing human input remains nt only where the schema explicitly requires it; a mistaken existing attestation is not automatically detected.

## One run, no repetitions

Each configuration has one scheduled unit for each listed scenario, not repeated trials. A/B/resume and fresh C serve different comparison roles; they are not statistical repetitions. There is no confidence interval or estimate of event frequency. Sampling, delayed uploads, server-side flags, account state, region, timing and model decisions can change results. A pass is an observation in this run; intermittent behavior can be missed, while a transient failure can produce fail or nt. Re-running creates a new batch and requires new adjudication rather than silently averaging results.

## Logged-in modes

Clients supporting a third-party model backend are tested without vendor login unless a separate logged-in run is explicitly reported. Their logged-in behavior is unknown. Vendor-hosted clients use the operator's account. Credential-like fields are scrubbed, credential headers hashed, and authentication request bodies omitted. Redacted payloads are uninspected for negative leakage and identifier findings, so logged-in L2-L5 often remain nt. Stable hashes can support a positive repeat finding, not prove absence. Account state may also affect behavior across fresh container HOMEs.
