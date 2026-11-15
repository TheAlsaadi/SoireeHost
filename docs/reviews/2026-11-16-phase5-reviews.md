# Phase 5 reviews

16 Nov 2026, branch `phase5-control-panel`.

## Pre-merge code review (`code-review` at high)

It found ten findings, all of them real, and all are fixed in commit `7a130e7`:

| # | Finding | Fix |
| --- | --- | --- |
| 1 | Proxy sites always forwarded to `127.0.0.1`. An app listening on `::1` only, as many Node servers on Windows do, got 502, while the status said the port was answering | Ports carry their address family, and `proxyTarget` picks `[::1]` when only IPv6 answers (`lib.test.ts`) |
| 2 | Activity rows were keyed by index, so the open request closed whenever new requests arrived | Entries are kept raw with stable ids |
| 3 | Declining a confirmation showed "Something went wrong" | `Declined` is ignored in the site form and first run |
| 4 | Every Activity poll reread whole log files | `logread.Files` skips files last written before the poll bound (`TestReadSkipsOldFilesWhenPolling`) |
| 5 | Security showed "On" with no data behind it, including when the service was down | Rows show "Not known" when the service does not answer, and the audit row until its check loads |
| 6 | Overlapping confirmations left the first waiting forever | A new confirmation declines one still open |
| 7 | The access-log reader was tested only with hand-made lines | The worker integration test parses the real `access.log`, and `TestFirewallInChain` matches each blocked request to its firewall event |
| 8 | The access-log reader duplicated the firewall-log reader | A shared `internal/logread` |
| 9 | The new dependencies were not recorded | `docs/DEPENDENCIES.md` |
| 10 | ADR-0009 described a navigation lock Wails cannot provide | ADR-0009 records the lock as built, and its limit |

## Security review (`security-review`)

The review was run by a separate reviewer over the whole branch, then filtered for false positives at confidence 8 or above.

**Result:** no findings.

**What it checked:**
- the confirmation tokens;
- the policy table;
- `access.list`, `config.import` and `config.export`;
- the readers of the untrusted log files;
- the pipe client;
- the worker failure text;
- `GrantSiteAccess`;
- every method bound to the UI;
- the frontend rendering of outside text;
- the bundle and dev-server CSP handling.

One observation below the bar was real and is fixed: `config.rollback` did not count weakened security headers, so rolling back to a revision that sent fewer headers needed no confirmation (`TestRollbackToWeakerHeadersNeedsConfirmation`).

Two other observations are recorded as decided behaviour:
- `Permissions-Policy` values are the user's choice and never count as weakening.
- Changing only directory listing on a live folder does not run the exposure check again. ADR-0009 makes listing an opt-in with a warning, not a confirmation.
