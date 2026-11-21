# SoiréeHost user guide

SoiréeHost puts a website or an app from your Windows PC on the internet through Cloudflare Tunnel. Your PC opens the connection outwards, so no port is opened on your router or PC, and visitors never learn your home IP address.

This guide covers installing, publishing a first site, getting a permanent address, protection, updates and uninstalling. For reporting a security problem, see [SECURITY.md](../SECURITY.md).

## Before you start

- **Windows 11, 64-bit (x64).** Other Windows versions are not tested or supported.
- **Administrator permission** for installing, repairing, updating and uninstalling. Windows asks for it each time; nothing else needs it.
- **Something to publish:** a folder of web files (for example an `index.html`), or an app already running on your PC on a port such as 3000 or 8080.
- **For a permanent address:** a domain on Cloudflare and a free Cloudflare account. Without one you can still share a site through a temporary link.

## Install

1. Download `soireehost.exe` and `SHA256SUMS` from the [latest release](https://github.com/TheAlsaadi/SoireeHost/releases/latest). Keep `soireehost.exe` in your Downloads folder.
2. Optional, but recommended: check the file. In PowerShell, in your Downloads folder:

   ```powershell
   (Get-FileHash .\soireehost.exe).Hash
   ```

   The result must match the line for `soireehost.exe` in `SHA256SUMS` (the letters may differ in case). If you have the GitHub CLI, `gh attestation verify soireehost.exe --repo TheAlsaadi/SoireeHost` also proves the file was built by the project's own CI.
3. Double-click `soireehost.exe`. The releases are not code-signed yet, so Windows may show **"Windows protected your PC"**. Choose **More info**, then **Run anyway**.
4. The **Install SoiréeHost** window lists every change it makes to Windows: the program in `Program Files\SoireeHost`, three services, two firewall rules that block incoming connections, a settings folder in `ProgramData\SoireeHost`, an entry in Settings > Apps, and the icon at sign-in. Choose **Install**, then **Yes** when Windows asks for permission.
5. The window closes and SoiréeHost opens.

If it says it **cannot install from this folder**, other accounts can change files in the folder you ran it from. Move `soireehost.exe` to your Downloads folder and run it from there.

## Put your first site online

The first time it opens, SoiréeHost shows **Put your first site online**:

1. **Choose what to publish:** a folder of files, or an app running on this PC (pick its port from the list, or type it).
2. **Choose how it goes online:**
   - **Quick share link:** a temporary `trycloudflare.com` address. No account needed. Good for testing and for showing someone a site.
   - **My own domain:** a permanent address through your Cloudflare tunnel. See [A permanent address](#a-permanent-address-on-your-own-domain).
3. **Go live.**

With a quick share link, the site's details show the address, with **Copy address**, **Show QR code** (for a phone) and **Open in browser**. The link is temporary: it changes whenever the tunnel restarts, for example after your PC restarts. Up to four sites can be shared this way at once.

To add more sites later, use **Add site** on the Sites page, or drop a folder onto the window.

### What SoiréeHost will not publish

Some folders are refused, so a mistake cannot expose your files: `Windows`, `Program Files`, `ProgramData`, the `Users` folder and each user's own profile folder (folders inside it, such as Documents, are fine), `AppData`, `.ssh`, and system folders at the root of a drive. A folder that links somewhere outside it is refused too. Inside a site's folder, hidden files such as `.env`, `.git`, private keys and backups are never served. A folder without an index page shows "not found" unless you turn on **List files in folders without an index page** for that site.

### Publishing an app

A proxy site forwards visitors to an app on your PC, for example `http://localhost:3000`. It can reach apps on this PC only, not other devices on your network. If the site shows **Port 3000 is not answering**, start your app, then check again.

SoiréeHost guards the way in to your app and keeps damage contained if the app is broken into, but it cannot fix flaws inside the app itself. Keep the app up to date.

## A permanent address on your own domain

This needs a domain whose DNS is on Cloudflare. **Note:** this mode is built and tested with a stand-in, but has not yet been verified end to end with a real domain.

1. In SoiréeHost, open **Settings > Tunnel token** and choose **Open the Cloudflare dashboard**.
2. In Cloudflare Zero Trust, go to **Networks > Tunnels** and create a tunnel of type **Cloudflared**. Give it a name.
3. Cloudflare shows install commands containing a long token. Copy only the token, paste it into **Tunnel token** in SoiréeHost, and choose **Save token**. SoiréeHost stores it encrypted and never shows it again.
4. Back in Cloudflare, add a **public hostname** for the tunnel, for example `blog.example.com`. For its service, enter the address SoiréeHost shows under **In Cloudflare, give each public hostname this service** (use **Copy service address**).
5. In SoiréeHost, edit the site and enter the same hostname under **Hostnames for a permanent address**.

The site's details then show **Serving through your tunnel**. Requests for any hostname that is not one of your sites get "not found".

## Protection

Each site has its own protection settings, shown in its details and changed with **Edit site**:

- **Firewall** (the OWASP Core Rule Set): **Block attacks** is the default and recommended. **Detect only** logs attacks but lets them through; **Off** removes the firewall for that site. Both are confirmed first, because they weaken protection, and the Security page lists every site where it is weakened.
- **Rate limit:** each visitor may make 300 requests a minute to a site.
- **Upload limit:** 10 MB per request; larger uploads are refused.
- **Security headers:** sent on every response, so browsers do not frame your site, guess file types or leak page addresses.

The **Security** page shows what protects your PC and sites right now. The **Activity** page lists requests as they arrive, including those the firewall blocked; choose one to see why. Text from visitors is shown exactly as sent and never run.

**Take everything offline** (at the top of the window, or in Settings) stops all tunnels at once, so no site can be reached from the internet. Switch it off to bring sites back.

## Settings and backups

- **Backups > Export settings** saves your sites and settings to a file. The tunnel token is never included. **Import settings** brings them back.
- **Backups > Earlier versions** keeps the last ten versions of your settings; **Restore** goes back to one.
- **Start at sign-in** keeps the SoiréeHost icon in the notification area after you sign in. Your sites are served by Windows services either way, even when the window and icon are closed.
- Every change is recorded in a change history that cannot be rewritten (**Security > Change history**).

## Updates

SoiréeHost checks GitHub once a day for a new version, and sends nothing about you or your sites. You can turn this off, or choose **Check now**, under **Settings > Updates**.

When an update is ready, choose **Install update**. Windows asks for permission, and your sites stop for about a minute while the new version starts. Before installing, SoiréeHost checks that the update is signed with the project's key and newer than the version you have; an update that fails a check is refused. If the new version does not start, the previous one is put back automatically.

Release candidates (versions ending in `-rc.1` and so on) are offered the next full release, not later candidates.

## Uninstall

Open Windows **Settings > Apps > Installed apps**, find SoiréeHost, and choose **Uninstall**.

- By default your settings, tunnel token and logs are kept in `ProgramData\SoireeHost`, so a later install picks up your sites again.
- Tick **Also remove settings, the tunnel token and logs** to remove everything.

A file that is still in use is removed the next time you restart the PC.

## Troubleshooting

| What you see | What to do |
| --- | --- |
| "Windows protected your PC" when starting the download | Expected while releases are unsigned: **More info**, then **Run anyway**. Check the file against `SHA256SUMS` first. |
| "Not connected: SoiréeHost's service is not answering" | Wait a minute after starting the PC. If it stays, restart the PC. If it still stays, Event Viewer (last row) says why; open an issue with what it shows. |
| "The tunnel program is missing or changed" | Choose **Repair** in Settings. SoiréeHost will not start a tunnel program that differs from the copy built into it. |
| The quick share link stopped working | Quick share links change when the tunnel restarts. Copy the new address from the site's details. |
| "Port N is not answering" | Your app is not running, or listens on another port. Start it and check again. |
| A site shows "not found" for a page you expect | The file may be hidden (starts with a dot) or the folder has no index page. |
| An update "failed its checks" | Nothing was installed. Try again tomorrow; if it repeats, report it privately (SECURITY.md). |
| Install, uninstall or a service did not work | Windows **Event Viewer > Windows Logs > Application** has entries from sources whose names start with `SoireeHost` (for example `SoireeHost Setup`) that say why. |

For other problems, open an issue on GitHub with your SoiréeHost version (Settings > About), your Windows version and the steps that cause it.
