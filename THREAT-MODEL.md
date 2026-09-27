# AgenticBench threat model (test definitions v0.2)

Agentic Thinking Ltd, 26 Sep 2026. Applies to test definitions v0.2 (`score/tests.json`).

## Whose side we take

The user of a coding agent on their own machine. The user has chosen an agent (the harness) and a model provider, and has accepted that the model provider will see the code, prompts and tool output the agent sends it. The question is what else happens: what the harness vendor and anyone else receive, whether the user was asked, and whether the user can switch it off.

We do not assume bad intent. We record behaviour on the wire and on disk and compare it with what the vendor says. What a recipient does with data after it arrives (retention, training, access) is **unknown** unless the vendor states it.

## Parties

| Party | Who it is | Example |
|---|---|---|
| User | The person running the agent | the tester, in a clean container |
| Harness vendor | Publisher of the agent software | the company or project that ships the agent |
| Model provider | The endpoint the user configured for model calls | the provider set in `rig.conf`, reached through the rig's capture proxy, for third-party-backend agents; the vendor itself for vendor-hosted agents |
| Third party | Anyone else | hosted analytics, error-reporting and monitoring services; also package registries, code hosts, CDNs |

When the harness vendor and the model provider are the same company (vendor-hosted agents, and any agent used with its vendor's own model), traffic to the model endpoint is still flow (a); other traffic to the same company is flow (b).

A telemetry service is classed by who operates it relative to the harness vendor, not by the product name. A telemetry service run by the harness vendor's own group is vendor telemetry, flow (b); a hosted analytics or error-reporting service run by another company is flow (c).

## The four flows

**(a) Traffic to the model provider.** The model request itself: prompt, context, tool output, and any headers or fields added to it. The user chose this recipient and already sends it their code, so identifiers and metadata here are **not scored as leaks**. They are reported as an informational row (I1: persistent identifiers sent to the model provider) because a reader may still care, for example when one API key is shared by a team.

Flow (a) covers what the model request needs to do its job. Data attached to model requests for a separate stated purpose (for example a field whose documented purpose is data collection) is treated as vendor telemetry, flow (b), even though it travels in the model request; such fields are identified by hand from the saved model requests (`METHOD.md`, endpoint classes). Identifiers stay in I1 either way.

**(b) The vendor's own telemetry.** Usage analytics, metrics, logs, install reports and error reports sent to the harness vendor, including to the vendor's domain when the vendor is also the model provider. Scored: whether it is on before consent (C1), whether the documented opt-out stops it (C3), whether it carries a persistent identifier (L2), file data (L4) or session content (L5), and whether it matches the vendor's privacy statement (C5).

**(c) Third-party telemetry.** The same kinds of data sent to a service operated by someone other than the vendor and the model provider. Scored as for (b), plus L1: whether any such service is contacted by default. Non-telemetry third-party traffic (package registry update checks, GitHub release downloads, model catalogues) is not a leak; it is listed in the informational host row (I2) and its opt-out behaviour is scored under C4.

**(d) Where the fake secret ends up.** The workspace holds a `.env` with two fake secrets. If the agent reads it, the secret is expected to reach the model provider (the user asked for it). L3 is scored on whether any secret form (value, base64, SHA-256/SHA-1/MD5) reaches anyone else. R5 is scored on whether it is left on disk outside the session record and the credential store.

## What is scored and what is only reported

| Flow or topic | Scored tests | Informational rows |
|---|---|---|
| (a) model provider | none | I1 identifiers to the model provider |
| (b) vendor telemetry | L2, L4, L5, C1, C3, C5 | I2 hosts by flow |
| (c) third-party telemetry | L1, L2, L4, L5, C1, C3, C5 | I2 hosts by flow |
| other third-party traffic | C4 | I2 hosts by flow |
| (d) fake secret | L3, R5 | none |
| no human present | N1, N2, N4, N5 | I3 exit code on refusal |
| the local record | R1, R2, R3 | I4 tamper evidence |

## Out of scope

- What servers do with data after receipt (unknown unless stated by the vendor).
- Logged-in modes of agents that can run with a third-party backend: they are tested with the configured model provider and no vendor login, so their logged-in behaviour is **unknown** unless tested separately. Vendor-hosted agents, which need an account to run at all, are tested logged in.
- Attacks on vendor infrastructure. We use normal API access, our own accounts and fake secrets only.
- Model quality, and whether the model refuses to read a secret (reported as `nt` for L3, not scored).

## Known limits of the evidence

- One run per configuration on one day; behaviour can depend on server-side flags we cannot see.
- A client that refuses our TLS interception is recorded as uninspected, and payload tests on that channel are `nt`.
- In logged-in runs the capture scrubber replaces the values of credential-like fields and headers (never a value that holds one of the unit's fake secrets), and authentication request bodies are not saved; such requests, and any request in which a value was redacted, count as uninspected, so payload and identifier tests on them are nt rather than pass.
- Binary request bodies and websocket frames that no known decoding turns into text (protobuf, msgpack, app-compressed data) are recorded as uninspected, so payload tests on them are nt. This analyser may miss a secret encoded or encrypted inside otherwise readable text when it cannot decode that representation. This is an implementation limit, not a claim about every passive-capture technique.
- Traffic the rig cannot tie to a request or a traced step (TLS server names or other-port destinations seen only in the packet capture) is recorded per unit and makes the payload and host tests of that unit nt.
- DNS query names are checked for literal needles and used for address association; external non-loopback UDP DNS is an uninspected channel. Encoded or split data in DNS names can still evade detection, especially through the namespace resolver.

The complete limitations, affected tests and error directions are in [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md).
