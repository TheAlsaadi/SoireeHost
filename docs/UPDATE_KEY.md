# The update-signing key

SoiréeHost trusts an update only if its manifest is signed by an Ed25519 key whose public half is compiled into the app (S-60, ADR-0004). This page is the written plan the release plan asks for (plan section 11): how the key is made, where it is kept, how it is replaced, and what to do if it is lost or stolen.

Whoever holds the private key can ship code to every install, so it is never committed, never pasted into a chat, an issue or a log, and never kept in only one place.

## Where the key lives

| Copy | Where | Who can use it |
| --- | --- | --- |
| Signing copy | The secret `UPDATE_SIGNING_KEY` of the GitHub environment `release` | Only the release workflow's `manifest` job, on a `v*` tag, after the owner approves the run |
| Offline backups | Two places the owner controls, for example an encrypted USB stick kept at home and an entry in a password manager | The owner |
| Public key | `internal/update/keys.json` in the repository, compiled into every build | Everyone; it is not secret |

The working copy on the PC is deleted once the secret and both backups are in place.

## Making the first key

Do this once, before the first real release (Phase 7). It needs no administrator rights.

1. Choose a folder **outside** the repository, for example `D:\keys\` on a USB stick. The tool refuses a path inside the repository.
2. In the repository, run:

   ```
   go run ./build/updatekey gen -out D:\keys\soireehost-update.key
   ```

   It writes the private key to that file, adds the public key to `internal/update/keys.json`, and prints the key's id. It never prints the private key.
3. Check the pair:

   ```
   go run ./build/updatekey check -key D:\keys\soireehost-update.key
   ```

4. Commit `internal/update/keys.json` through a pull request. Releases built after it is merged trust the new key.
5. Create the release environment (GitHub > the repository > Settings > Environments > New environment):
   - name: `release`;
   - **Required reviewers:** the owner;
   - **Deployment branches and tags:** Selected branches and tags, then add the tag rule `v*`;
   - **Environment secrets > Add secret:** name `UPDATE_SIGNING_KEY`, value the one line of text in the key file.
6. Make the two offline backups of the key file.
7. Delete the key file from the PC, and empty the recycle bin.

## Checking the backups

Once a year, and before any rotation, run `updatekey check -key <backup>` against each backup. A backup that fails the check is replaced from the other one at once.

## Replacing the key (planned rotation)

A binary trusts at most two keys, so a planned rotation takes three releases:

1. **Release N** ships with both keys. Run `updatekey gen` for the new key; `keys.json` then lists the old key and the new one. Release N is still signed with the old key.
2. **Release N+1** is signed with the new key: replace the `UPDATE_SIGNING_KEY` secret with the new key before tagging it. Installs that took release N trust it.
3. **Release N+2** drops the old key from `keys.json`. Destroy the old key's backups after that release.

Users who skip release N cannot verify N+1. The release notes of N+1 say so, and those users install N first, or reinstall by hand.

## If the key is stolen

Anyone with the key can sign an update that every install trusts, until those installs stop trusting it.

1. Delete the `UPDATE_SIGNING_KEY` secret at once, so the release workflow cannot use the key, and stop all releases.
2. Make a new key as above.
3. Publish a release whose `keys.json` holds **only the new key**, signed one last time with the old key, so existing installs can verify it. Publish a security advisory saying what happened, and asking every user to install that release now, or reinstall from the release page.
4. Sign every later release with the new key.

Until a user installs that release, the thief can still ship them a forged update. This is the limit of a single key (ADR-0004, Option D); signing with SignPath later adds a second, independent check (S-61).

## If every copy of the key is lost

Existing installs can no longer verify any update. Make a new key, publish a release that trusts only it, and tell users to download that release and install it over their current version by hand. Settings, the tunnel token and logs are kept by an install over an existing one.
