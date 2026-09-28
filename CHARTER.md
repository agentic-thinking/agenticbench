# AgenticBench governance charter

Version 1, 26 Sep 2026; independence wording updated 28 Sep 2026. AgenticBench is run by Agentic Thinking Ltd, an independent research lab in the UK.

## 1. What the benchmark is for

To tell users what an AI coding agent does on their machine, compared with what its vendor says: what leaves the machine and to whom, whether consent and opt-outs work, what happens with no human present, and whether the agent's own record is usable. It does not measure how well an agent codes.

## 2. Independence and conflict of interest

Agentic Thinking is a research lab. It has developed AI agent governance and workflow software, none of which is for sale, and we will never score our own software on AgenticBench. The benchmark takes no vendor money (section 4). A benchmark that finds gaps in agent records and approvals could still be read as favouring the lab's own approach to governing agents. So:

- **Tamper evidence of the record is not scored.** Because the lab has developed software in this space (governance of agent records and approvals), scoring it could tilt results towards the lab's own approach. It is reported as an informational row (I4) with its evidence.
- Categories, tests and thresholds are published with their rationale before results, and every change is versioned (`score/tests.json`, `METHOD.md`).
- The rig, scorer and test definitions are published so anyone can re-run the tests and check a result without trusting us; the captures behind published results are published with those results.
- We seek at least one external reviewer for each version of the test definitions and name them when they agree to be named.
- Any page that shows results carries this disclosure.

## 3. How categories, tests and thresholds are set

- Tests are yes or no questions about observable behaviour, each with a written procedure and evidence rule (`METHOD.md`), and are mapped to a published threat model (`THREAT-MODEL.md`).
- Where a vendor documents a behaviour, the test asks whether the agent behaves as documented, not whether we like the design. A documented auto-approve mode that runs commands is not a failure.
- Data sent to the model provider the user chose is not scored as a leak; it is reported.
- Every agent is scored out of the same 18 tests. A missing safeguard counts as a fail; "Not tested by us" covers only our own test limits, and "Held" covers results held while a disclosure to the vendor is open. The chart is ordered by tests passed, then fewest failures; it is not a certification.
- Changes to tests or thresholds are proposed in the open, take effect in a new version, and are applied to all agents at once. Old results stay published under the version they were scored with, or are re-scored from the same captures and marked as such.

## 4. Money

- No vendor pays to be included, excluded, tested, re-tested or rated. We accept no sponsorship, advertising or donations from vendors of tested agents.
- There will never be a paid certification, seal, "verified" badge or any paid change to a result.
- If the lab ever sells anything around the benchmark (for example alerts when a new release changes behaviour, or procurement reports), the public results stay free and identical for everyone.

## 5. Vendors

- Findings go to the vendor privately first, under the disclosure policy (`DISCLOSURE.md`).
- Vendor replies are published verbatim alongside the result, unless the vendor asks us not to publish their words, in which case we say that they replied and summarise the substance without quoting.
- A vendor may dispute a result. We re-test on request with any configuration the vendor documents, publish the re-test and its outcome, and note the dispute on the result until it is resolved.
- We do not test vendor servers beyond normal use, and we use fake secrets and our own accounts only.

## 6. Corrections

- Errors are corrected on the page where they appeared, with the date, what changed and why. We do not silently edit results.
- Owned errors in method (for example a rig defect that invalidated a run) are recorded in the published run notes.

## 7. Evidence standard

- Every pass or fail cites captured evidence: wire capture, strace, file on disk or a hashed documentation snapshot.
- Agent-run and agent-checked results are triage until a person replays the headline results from the raw captures. Preliminary results are labelled as such.
- What a vendor does with data after it leaves the machine is unknown unless the vendor states it.
