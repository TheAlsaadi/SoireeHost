# Security policy

SoiréeHost puts websites on the internet from a home PC, so a flaw in it can expose that PC. Reports of security problems are very welcome.

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through GitHub:

1. Open the repository's [Security tab](https://github.com/TheAlsaadi/SoireeHost/security).
2. Choose **Report a vulnerability**.
3. Describe the problem, the SoiréeHost version (Settings > About), your Windows version, and the steps to reproduce it.

Only the maintainer sees the report. You will get an answer as soon as possible, usually within a week. Once a fix is released, a security advisory credits you unless you prefer not to be named.

Please give a fix time to reach users before you publish details. SoiréeHost checks for updates once a day, so most installs are offered a fixed release within a day of it being published.

## Supported versions

| Version | Supported |
| --- | --- |
| The newest release | Yes |
| Release candidates (`-rc.N`) | Until the release they lead to is out |
| Anything older | No: update first |

Security fixes in Caddy, Coraza, the OWASP Core Rule Set, cloudflared and Go are shipped in a SoiréeHost release, with a target of 7 days after the upstream fix.

## What counts

In scope: anything that lets someone on the internet, another program on the PC, or another Windows account do more than SoiréeHost intends. For example:

- reaching the PC or the local network other than through a published site;
- reading files outside a site's folder, or hidden files such as `.env` and `.git` that SoiréeHost refuses to serve;
- getting past the web application firewall's Block mode with a request it should stop;
- reading the tunnel token or other secrets, or changing settings without the control panel's confirmations;
- making an update install that the maintainer did not sign;
- script running in the control panel from text visitors send.

Out of scope:

- flaws inside an app or site you host with SoiréeHost: it guards the way in and limits the damage, but cannot fix the app;
- anything that needs administrator rights on the PC already;
- denial of service by flooding the tunnel (Cloudflare's side) or the PC's internet connection;
- Windows SmartScreen warning about an unsigned download (see the README).

## What has and has not been checked

SoiréeHost is built and maintained by one person. Every security requirement in [docs/SECURITY_CHECKLIST.md](docs/SECURITY_CHECKLIST.md) has an automated test or a recorded manual check, and each release runs static analysis, fuzzing and a set of review tools. **No independent security review or paid audit has been done yet.** If you are able to review the design or the code, a private report is the best way to share what you find.

The design and the threat model are in [docs/PLAN.md](docs/PLAN.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
