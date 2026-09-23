# Capability integrity verification

farcmd verifies, immediately before every level 3, 4 and 5 execution, that the remote command
capability is still exactly what farcmd provisioned. Verification works after the master key has
been deleted, gives the verifier no shell, and a modified verifier cannot report "unchanged".

## 1. What was there before, and why it was replaced

The previous implementation (`verifyCommandCapabilityIntegrity` in `src/ssh.ts`) ran an ad-hoc shell
command **with the master key** (`sha256sum "$path"; grep -Fqx "$key" ~/.ssh/authorized_keys`) and
compared the printed hash with the stored baseline. Problems:

| Problem | Consequence |
|---|---|
| Used the master key | L3–L5 stopped working when the master was deleted or locked, which contradicts the master-deletion semantics. Every L3–L5 call also used a full-shell credential. |
| Unauthenticated output | Anything running as the target account (`~/.bashrc`, a PATH-planted `sha256sum`, a replaced script) could print the expected hash. |
| Tautological key check | `actualAuthorizedKeySha256` was computed locally from the stored line. It only checked that the line existed, not that it was the *only* line for that key. An unrestricted duplicate of the command key went undetected. |
| Broken in practice | `"~/.ssh/farcmd/…"` was quoted, so `~` never expanded. The output-splitting regex was double-escaped. The installer's `$(…)` stripped trailing newlines, so the remote script never matched its stored hash. |

A plain "`verify.sh` returns SHA-256 of the files" cannot be fixed by tweaking. A SHA-256 value is
only evidence if you trust the process that computed it, and a script the target account can
modify gives no such trust.

## 2. Threat model

**Attacker:** anyone who can act as the target SSH account: edit its files (`~/.ssh/authorized_keys`,
`~/.ssh/farcmd/*`, shell rc files), run processes as it, and replace anything it owns.

**Detected / prevented**

- manual modification or replacement of a command script
- modification, removal or duplication (for example an unrestricted copy) of a farcmd-managed
  `authorized_keys` entry, in `authorized_keys`, `authorized_keys2` or any `AuthorizedKeysFile`
  sshd actually uses
- unexpected files in farcmd's capability namespace (`~/.ssh/farcmd/<mcp-host>-*`)
- a fake or modified verifier that reports the old expected state (fails the MAC check)
- replay of an earlier genuine verifier response (wrong nonce)
- damaged or missing verification infrastructure (blocks execution, with no unverified fallback)

**Not in scope, stated plainly**

- **Root on the target.** Root can read the secret, replace the verifier, or change sshd. A verifier
  running on a fully compromised host can't be an external root of trust. The same applies if the
  target account has **unrestricted sudo**: it is effectively root. The trust boundary requires the
  target account *not* to have general root.
- **Compromise of the farcmd server or its database.** The expected state lives there.
- **An attacker actively racing execution as the target account.** See §7 (TOCTOU). Verification
  proves the capability was intact at measurement time. It can't stop an account that is changing
  files around the check, or that hijacks execution through its own shell start-up files. The
  capability executes *as that account*.

## 3. Three authorities, cryptographically separated

```
MASTER KEY (ssh_keys)             provisioning authority
  ├── install / replace / remove command capabilities
  └── install / repair the verifier  (needs root on target: root account or sudo)

VERIFICATION AUTHORITY            per target, table verification_authorities
  ├── verification key            forced to the root-owned verifier only
  └── verification secret         32-byte HMAC key, also stored root-only on the target

COMMAND KEY (command_installations)   execution authority for exactly one capability
  └── forced to ~/.ssh/farcmd/<mcp-host>-<command-id>.sh
```

- Three independent Ed25519 keys, each encrypted at rest with AES-256-GCM under **different AAD
  namespaces**: `ssh-key:<user>:<id>`, `verification-key:<user>:<id>`,
  `verification-secret:<user>:<id>`, `command-installation:<user>:<id>`. A ciphertext from one
  role can't be decrypted as another.
- Verification authorities live in their own table. They can never be picked as a master and they
  are not deleted with one. Nothing in the execution path reads `ssh_keys`.
- None of these is ever returned through MCP. MCP only sees `id, name, description, level,
  enabled, confirmation` (tested in `test/security.test.ts`).

## 4. Remote layout (created by the installer)

| Path | Owner / mode | Purpose |
|---|---|---|
| `/usr/local/libexec/farcmd/verify-<id>` | root:root 0755 | Verifier (Python 3 stdlib, run as `python3 -IS`) |
| `/etc/farcmd/verify-<id>.key` | root:root 0600 (dir 0700) | HMAC secret |
| `/etc/sudoers.d/farcmd-verify-<id>` | root:root 0440 | `<account> ALL=(root) NOPASSWD: /usr/local/libexec/farcmd/verify-<id> ""` |
| `~<account>/.ssh/authorized_keys` | account | `restrict,command="sudo -n /usr/local/libexec/farcmd/verify-<id>" ssh-ed25519 … farcmd-verify:<id>` |

- The sudoers rule allows **only** that program with **no arguments** (`""`). sudo resets the
  environment, so the only input the verifier ever receives is its stdin.
- `restrict` disables PTY, port, agent and X11 forwarding and `~/.ssh/rc`. OpenSSH ignores the
  client's command for a forced-command key.
- The verifier is Python rather than sh because it runs as root while reading account-controlled
  paths. It walks directories with `openat(O_NOFOLLOW|O_DIRECTORY)`, opens files with
  `O_NOFOLLOW|O_NONBLOCK` and checks `fstat` (type, owner, inode) on the opened descriptor. It
  hashes only regular files owned by the account. A planted symlink, FIFO or hard link to a root file
  therefore can't make root read, block on, or leak the hash of another file.
- Root never writes into the account's home. The `authorized_keys` line is placed through
  `runuser -u <account>` (fallback `su`).
- Target requirements: Linux, `python3` in a root-owned system location, `sudo` (unless the target
  account is root), coreutils, `runuser` or `su`.

## 5. Protocol

```
farcmd                                            target (sshd → sudo → root verifier)
  N = 32 random bytes (hex)
  ── SSH, verification key, exec "farcmd-verify" (ignored by sshd)
     stdin: "FARCMD-VERIFY 1 <N>\n" ───────────►  accept only ^FARCMD-VERIFY 1 [0-9a-f]{64}\n$
                                                  read root-only secret K
                                                  measure (§6)
     ◄──────────────────────────────── stdout:    B = canonical lines, ending "end\n"
                                                  "mac " HMAC-SHA256(K, B) "\n"
  1. response is ASCII, not truncated, ≤ 4 MiB
  2. HMAC-SHA256(K, B) == mac   (constant time; nothing is parsed before this)
  3. strict grammar; nonce == N; verifier id, account match
  4. compare measurement with farcmd's own records
```

Example body (real output from the e2e test, shortened):

```
farcmd-verify 1
nonce 8207004a…af9b
verifier 0d2a20fa-e1d9-4d9f-90ed-e1f3effb171a
user fce2e2e447d 1003
python /usr/bin/python3.11 ok
self e5ca10e4…f893 ok
secret ok
sudoers 850b2509…ef0e ok
home ok 1003 0750
capdir ok 1003 0700
cap mcp.e2e.test-22e81a42-….sh f 1003 0500 1 174 7d8bd560…028f
sshd ok none
akf 0 .ssh/authorized_keys ok fd77ebe8…23df
ak 0 1 d189b99c…ff98 4ce3d2e1…92c9
akf 1 .ssh/authorized_keys2 absent -
end
mac cde4c18d…fb46
```

Why this can't be forged:

- **Fake verifier:** anything the account can put in the verification path (a replaced forced
  command, a PATH-planted `sudo`, a `.bashrc` hook) can't read `K`. So it can't produce a valid MAC
  for the "expected" state. Tested with a fake that replays the captured genuine measurement under
  the live nonce: *invalid MAC → blocked*.
- **Replay:** a captured genuine response carries its own nonce inside the MAC. Tested:
  *stale or replayed → blocked*. Timestamps are not used.
- **Relaying to the real verifier** gives only the true measurement, and the real verifier can't be
  told what to measure.

## 6. What is measured and what it is compared with

For each target, farcmd knows what it provisioned (`command_installations`): script content and
SHA-256, the exact `authorized_keys` line and its SHA-256, the remote path, the command public key,
and the SHA-256 of the command definition (`type\0content`).

| Measured (inside the MAC) | Expected by farcmd | Block scope |
|---|---|---|
| `self`: SHA-256 of the verifier file + root-ownership of every path component | SHA-256 of the program farcmd rendered (with the interpreter recorded at activation) | all |
| `python`: interpreter path + root-ownership chain | allow-listed path recorded at activation | all |
| `secret`: root-only 0600 | `ok` | all |
| `sudoers`: SHA-256 + root-ownership | SHA-256 of the rule farcmd rendered | all |
| every `authorized_keys` line of every `AuthorizedKeysFile` (from `sshd -T`): SHA-256 of the line + SHA-256 of every key blob in it | verification key blob appears in **exactly one** line, and that line hashes to the stored line | all |
| same, for each command key blob | exactly one line, equal to the stored line | that command |
| `~/.ssh/farcmd` entries: name, type, owner, mode, link count, size, SHA-256 | each script: regular file, owned by the account, 1 link, not g/o-writable, SHA-256 = stored script hash | that command |
| entries named `<mcp-host>-*` | only current installations or ledger-pending (stale) ones | all |
| home and capability directory owner/mode; unsafe or symlinked key files | owned by the account (or root), not g/o-writable | all |

farcmd additionally checks locally, before any network access, that the stored command definition
hash, script hash and `authorized_keys` hash are self-consistent.

A problem in *another* command's script blocks only that command. Problems with the verifier, the
verification key, account-level state or the namespace block every L3–L5 command on the target.

## 7. Execution sequence and TOCTOU

```
L1/L2  request → local DB consistency → execute                         (unchanged)
L3     request → [verify ∥ authenticate execution connection] → exec
L4     request → human approval → [verify ∥ authenticate] → exec
L5     request → per-command password → [verify ∥ authenticate] → exec
```

No verification means no execution: a missing, pending, unreachable, failing or mismatching
verifier blocks the call. The blocked attempt is written to `execution_history` with status
`blocked`, plus a `security_events` entry (`integrity_verification_blocked`).

**TOCTOU.** The script is read by root during verification and read again by sshd/bash at
execution. farcmd shrinks that window: the execution connection is opened and authenticated **in
parallel** with verification (authentication runs nothing on the target). The `exec` request is
sent only after the MAC and all comparisons succeed. The remaining window is one SSH channel round
trip plus process start-up (milliseconds), instead of a full SSH handshake.

The window can't be closed while scripts are owned by, and executed as, the target account. Such an
account can restore a file for the check and swap it back, or hijack the forced command through its
shell start-up files. This is acceptable under the threat model: verification catches persistent
tampering, accidental edits and fake verifiers, and anyone able to win that race can already run
arbitrary code as that account. Closing it fully would need root-owned capability scripts and a
root-owned `AuthorizedKeysFile`, meaning every capability install needs root. That is a possible
future hardening mode, not part of this change.

## 8. Lifecycle

| Event | Behaviour |
|---|---|
| Target created | No verifier: L3–L5 blocked (the UI says so on the SSH and Commands pages). L1/L2 work. |
| **Install, automatic** (`POST /api/ssh/targets/:id/verifier`) | Needs the unlocked master **and** root via that master (root account or `sudo -n`). The installer is piped to `sudo -n sh -s` on **stdin**, so the secret is never in argv. farcmd then runs a verification and activates. |
| **Install, manual** (`POST …/verifier/manual`) | Works **without any master**. farcmd shows the root install script once (it contains the secret). An administrator runs it as root, then clicks *Verify now*. Recommended when the master account should not have root. |
| Activation | The first authenticated response whose verifier-level checks pass sets `status=active` and records the interpreter path and verifier hash. Until then, L3–L5 are blocked. |
| **Master deleted** | Allowed as before. Verification uses only the verification key and secret, so L3–L5 keep working (tested for L3, L4 and L5). Provisioning, replacement, automatic verifier repair and remote cleanup become unavailable (tested). Local removals go to the remote-capability ledger, and ledger-pending scripts are tolerated by the namespace check. |
| Verifier damaged (file missing, secret replaced or loosened, sudoers changed) | Verification fails → L3–L5 blocked, error shown in the UI. |
| Repair | Automatic (needs a master with root) or manual root script (no master needed). Repair keeps the verifier id and rotates the key and secret. The old `authorized_keys` line is replaced, not duplicated. |
| New master uploaded later | Can provision again, run ledger cleanup, and repair the verifier automatically if it has root. |
| Verification authority removed (`DELETE …/verifier`) | L3–L5 blocked. Remote removal uses the master if possible; otherwise a root uninstall script (no secrets) is shown. |
| Target deletion | Refused while a verifier (or installed capability) exists. |

**Install-time trust.** Automatic installation runs through the target account's SSH session, so it
assumes that account is not compromised *at install time* (its shell start-up files run before
`sudo`). The manual root script avoids that assumption.

## 9. Trust boundary summary

| Question | Answer |
|---|---|
| Who can read the verification secret? | Root on the target (file root:root 0600 in a 0700 root directory). farcmd, encrypted at rest. Never the target account, never MCP/AI. |
| Who can modify the verifier? | Root on the target only: file, directory chain and interpreter chain are root-owned and not group/world-writable. The verifier checks this chain itself, and farcmd checks the verifier's hash. |
| Who can modify command scripts / `authorized_keys`? | The target account (and root). That is exactly what verification detects. |
| What does the verification key allow? | Starting the verifier with a stdin challenge. No shell, no arguments, no PTY, no forwarding (tested against a positive control). |
| Fully compromised (root) target? | Out of scope. Root can read the secret and forge responses. farcmd can't detect a root-level adversary from inside the host. |

## 10. Tests

- `npm test` (no privileges): protocol and evaluation (`test/verification.test.ts`) covering forged
  MAC, replay, missing nonce, malformed/truncated/non-canonical responses, script/key/namespace
  problems and problem scoping, installer artifacts, and the verifier rejecting every non-canonical
  request. Also the MCP information boundary and L3 blocked without a verifier (with history and
  audit rows) in `test/security.test.ts`.
- `sudo -E npm run test:e2e`: a real `sshd`, a real unprivileged account, the real verifier and
  sudo (`test/integrity.e2e.test.ts`). Covers every scenario in this document, including the fake
  verifier, replay, master deletion, manual repair and forced-command restrictions. Runs in CI as
  the `integrity-e2e` job.
