# AgenticBench disclosure policy

Version 1, 26 Sep 2026.

## Two tracks

| Track | What it covers | Window before publication |
|---|---|---|
| Behaviour versus documentation | The agent does something its documentation, privacy statement or settings do not describe, or describe differently (for example telemetry that a privacy page says is not collected, an opt-out that does not stop what it says it stops) | About 30 days |
| Security vulnerability | A flaw that lets someone other than the user read, change or exfiltrate data, or run commands, beyond what the user authorised | 90 days |

## Process

1. We write to the vendor's security or privacy contact with what we observed, the version, the evidence, and the planned publication date.
2. The vendor can ask questions, get the captures and exact commands, and ask for more time. We extend the window when a fix is in progress and the vendor says so, and we allow for holidays.
3. If a vendor ships a fix, we re-test the fixed version and publish both results.
4. The vendor's reply is published verbatim with the result (see the governance charter for exceptions).
5. Until the date, the affected results are shown as "Disclosure sent to vendor" with the date, and no detail is published.
6. If a finding is being actively exploited or users are at immediate risk, we may shorten the window; we will tell the vendor first.

## Before anything is sent

- Every disclosure is checked against the evidence by an independent second reviewer and a person replays the key result from the raw capture.
- Wording is version-precise and proportionate, and credits what the vendor gets right.
