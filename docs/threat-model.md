# Threat Model

## Scope

This model covers the alpha's local configuration, credential providers, token cache, HTTP client, raw request escape hatch, structured output, and typed entity reads. It does not approve future mutation, SSO callback, configuration-apply, task-cancel, or package-distribution designs.

## Protected Assets

- Client secrets, bearer tokens, refresh tokens, authorization codes, and credential-process output.
- Tenant identity and production intent.
- Reltio entity data and filters, which may contain personal or sensitive business information.
- Cursor values and resume state.
- Integrity of endpoint/practice policy and release artifacts.

## Trust Boundaries

1. Shell and process environment to CLI process.
2. Local config/cache/state filesystem to CLI process.
3. Credential process to auth provider parser.
4. CLI HTTP client through proxy/DNS/TLS to configured Reltio services.
5. Upstream response to structured stdout/stderr.
6. Maintained policy YAML and test evidence to build output.

## Threats And Controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Secret in shell history/process list | No secret-valued CLI argument; hidden prompt, stdin, environment, file, or process | Environment remains visible to sufficiently privileged local processes |
| Token cache read by another user | Owner-only mode plus ACL checks on Unix; protected process-user-only creation DACLs and same-handle policy checks on fixed local Windows drives; links and reparses refused | A process running as the same SID or with backup/restore or administrative privileges remains in the trust boundary |
| Concurrent token storm | Cross-process lock plus cache recheck; reuse until expiry | Locks do not coordinate unrelated machines |
| Login crash or concurrent profile change | Candidate cache is staged under the exclusive maintenance lock; displaced generations remain usable; profile commit is compare-and-swap; ordinary failure restores and verifies the candidate preimage before readers continue | A process killed between cache and profile commit can leave an unused owner-only candidate token until expiry or explicit logout, but does not delete the old profile's usable credential |
| Profile removal leaves an imported bearer orphan | Success output is preflighted; cache deletion and exact preimage rollback occur under the exclusive maintenance lock before configuration commit; committed/uncertain outcomes report profile and cache state | Abrupt process death after cache deletion but before profile commit can leave the profile without its bearer; explicit login or logout repairs that local state |
| Fixed-size/UUID token assumption | Opaque secret type and multi-kilobyte contract tests; access and refresh tokens are bounded only by a 1 MiB local ceiling | The local ceiling can reject a future larger provider token |
| Credential-process substitution | Absolute owner-private executable; no shell; Windows requires a self-contained `.exe` as the only entry in a non-plantable directory, restores default DLL search state, retains no-data-write/no-append/no-delete-share executable and ancestor handles through process creation, uses that directory as working directory, and removes inherited `PATH` | Mutually hostile same-identity or privileged processes and previously granted metadata/DAC/owner handles remain in the local trust boundary |
| Credential process survives timeout or cancellation | One absolute command deadline; cancellation-aware process wait; Unix separate process group with group termination and reaping; Windows suspended creation followed by fail-closed assignment to a kill-on-close Job Object before resume | A deliberately self-detaching Unix broker or privileged process can escape process-group cleanup; configured broker executables are trusted not to do so |
| Timeout or SIGINT commits late state | One absolute deadline across auth, locks, HTTP, and response reads; sticky cancellation observed by an independent signal task; pre-commit checks and explicit local/remote completion metadata | A signal or deadline can race with a local commit point or in-flight remote operation, so callers must honor reported replay safety |
| Secret in diagnostics or raw responses | Protected headers, every token-generation replacement including bounded common encodings, conservative over-depth/oversized-encoding redaction, exact final-render checks across data, generated metadata, and appended newlines, all-cache-generation login guards, fail-closed malformed-cache guards, guarded error rendering, diagnostic sensitive-key redaction, raw credential-field redaction, bounded bodies, duplicate/deep/high-complexity JSON refusal, and no raw terminal output; explicit token disclosure exempts only the selected access token while retaining cumulative guards for distinct credentials and generated errors | Arbitrary PII and ordinary successful typed entity fields are intentionally preserved; in the irreducible case diagnostics are omitted |
| Credential exfiltration by redirect | Redirect policy is `none`; redirect becomes a safety error | Compromised configured same-origin server still receives auth as intended |
| Wrong-tenant request | Tenant resolves independently and is embedded in data base URL; traversal is refused | Read commands do not require repeated tenant confirmation |
| Raw header/query override | Authorization, Host, cookies, proxy, framing, forwarded headers, and secret query keys refused | Other endpoint-specific sensitive keys require registry updates |
| Duplicate mutation through retries | Replay decision precedes status policy; typed mutations are absent and actual raw mutations fail closed until the audit-result contract has implementation evidence | Mutation support remains unavailable rather than accepting an unauditable outcome |
| Unbounded response memory | Streamed bounded response reader; scans process one page at a time; table output caps distinct columns and row-column cells and does not materialize a dense matrix | One finite response or scan page is parsed in memory |
| Cursor resume skips/duplicates | Endpoint, exact CLI version, target, service route, context/query hash, page size, coherent cursor/sequence/timestamps, registry expiry bounding authentication and all retries, UTF-8 metadata path, single-owner lock, output-before-state commit, and whole-page checkpoints | Server-side cursor semantics remain an upstream dependency |
| Stale API guidance | Source-linked registry, upstream lock, scheduled drift report, 14-day release gate | Documentation can lag deployed tenant behavior |
| Policy or release claims without tests | Build joins endpoint, practice, release-requirement, acceptance-scenario, contract-field/result, and test-evidence IDs; exact compiled operation/safety/binding inventories prevent count-only substitution; stable-tag CI executes the attributed tests and binds tag/manifest/package versions | Function attribution does not prove live-tenant behavior, so platform and pilot gates remain separate |

## Unix Filesystem Boundary

Private reads, atomic writes, and lock creation on Linux, macOS, and FreeBSD normalize paths lexically, open the filesystem root, and traverse each original parent with descriptor-relative `openat` plus `O_NOFOLLOW`; they never canonicalize a caller-controlled path. Intermediate and final symbolic links are refused. A narrow set of root-owned, root-level filesystem aliases (`/etc`, `/home`, `/tmp`, and `/var`) may have their link target read before traversal because only a privileged process can replace a root-directory entry. Parent-directory (`..`) components are refused.

Each opened ancestor must be root- or process-user-owned and must not grant group/other mutation rights; a root-owned sticky directory is accepted with raced children still subject to owner, type, ACL, and identity validation. ACL mutation grants are checked and every ancestor name is revalidated against its held descriptor before commit. Reads and locks open the final component relative to the pinned parent and compare named/open identities. Private files must be regular, single-link, process-user-owned, mode `0600`, and free of non-owner allow ACLs.

Atomic writes create a random `0600` same-directory file with `openat(O_CREAT|O_EXCL|O_NOFOLLOW)`, clear inherited ACLs before writing secret bytes, flush and revalidate the held object, and install it with descriptor-relative `renameat`. Temporary cleanup unlinks only when the temporary name still identifies the held inode, and rename success disarms cleanup before directory durability is reported. Path-based ACL library calls run only inside the already pinned, mutation-checked namespace; mutually hostile same-UID processes remain in the local trust boundary.

## Windows Filesystem Boundary

The private `reltio-windows-security` crate is the only workspace location allowed to contain Windows FFI. It uses the process primary token SID, not a path owner alias or an impersonating thread identity. New files and directories receive a self-relative security descriptor through `SECURITY_ATTRIBUTES` at creation. The descriptor sets that SID as owner and has one protected, non-inherited full-control allow ACE for that SID; it does not add a LocalSystem ACE. Secret bytes are written only after the returned handle passes policy inspection.

All accepted input paths are normalized to drive-absolute paths that Windows classifies as `DRIVE_FIXED` before any existence or metadata I/O. UNC, mapped/remote and Windows-classified removable drives, caller-supplied verbatim/device namespaces, rooted-without-drive and drive-relative paths, alternate data streams, reserved DOS device names, trailing separators, trailing current-directory components, trailing-dot aliases, and trailing-space aliases are refused. Some external devices report `DRIVE_FIXED`; physical non-removability is therefore not claimed. Each arbitrary-path open uses identification-level security QoS, opens the final component itself rather than following it, requires a disk handle, and rejects reparse attributes or tags from that handle. Private files additionally require one link, process-user ownership, a present non-NULL protected DACL, and exactly the expected allow ACE. Bounded readers exclude write sharing but permit delete sharing, producing a stable old-object snapshot while another process atomically replaces the path.

Traversal is a fail-closed ancestor scan rather than an NT handle-relative traversal. Every ancestor is opened one component at a time without write or delete sharing, checked from that same handle for disk-directory and non-reparse state, and checked for an owner and DACL that prevent deletion, ACL takeover, or replacement by an untrusted principal. Directory add-file/add-subdirectory rights alone are accepted because they cannot replace an existing child; every raced child is still opened no-follow and validated. The restrictive share mode makes the scan fail while an existing data-write, append, or delete access handle conflicts with the guard. Current-user, LocalSystem, built-in Administrators, and TrustedInstaller owners or mutation ACEs are treated as inside the privileged trust boundary. Unsupported allow ACE forms fail closed. Ancestor handles remain open and are revalidated around the final operation. This blocks path substitution by a different non-privileged SID; it does not claim to isolate mutually hostile processes running as the same SID, a privileged principal, or a principal retaining a previously granted `WRITE_DAC`/`WRITE_OWNER` handle. Destination installation remains path-based through `MoveFileExW`, so mutation by those explicitly privileged actors is outside this boundary.

Credential-process paths additionally require an explicit case-insensitive `.exe` extension. Their immediate parent rejects untrusted file and subdirectory creation rights and must contain exactly one entry: the validated executable. Existing sibling DLLs, `.local`/SxS directories, and other app-local dependency trees are refused, so this alpha supports only self-contained Windows broker binaries whose remaining dependencies resolve from protected operating-system locations. The final no-follow handle and all ancestor handles exclude data-write, append, and delete sharing and remain live from policy validation until `CreateProcess` returns, closing the path replacement window without preventing Windows from opening the image for execution. The CLI calls `SetDllDirectory(NULL)` before spawn, restoring the default order and Safe DLL Search Mode according to the machine registry setting. The child is created suspended, assigned to a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and resumed only after assignment; any creation, assignment, or resume failure terminates the child and fails authentication. Closing the Job Object on timeout, cancellation, or process exit terminates the contained process tree. The child starts in the guarded executable directory and does not inherit `PATH`, removing inherited custom DLL directories, the caller directory, and path entries from dependency search. Sharing restrictions do not exclude attribute or extended-attribute access; pre-existing metadata, `WRITE_DAC`, and `WRITE_OWNER` handles held by actors already inside the documented trust boundary remain residual risks.

Atomic writes use a randomly named same-directory file with the private creation descriptor, validate and flush its contents, revalidate pinned ancestors and any existing destination, and install it with replace and write-through rename flags. All fallible policy checks occur before rename. A successful rename is the commit point and immediately disarms temporary cleanup, so an error cannot delete or truncate the installed destination. Pre-commit cleanup marks the same temporary-file handle for deletion, avoiding a second path lookup. A process killed before cleanup can leave a private random temporary; cache logout identifies only the exact random-name form, verifies its private policy through a no-follow handle, and removes it by handle. Lock creation uses the same creation descriptor; an existing lock is only opened and verified, never re-ACL'd. Lock handles permit read/write sharing needed by cooperating processes but exclude delete sharing.

## Explicit Non-Controls

- TLS verification cannot be disabled.
- Core redaction cannot be disabled.
- No analytics or product telemetry is transmitted.
- No remote audit store is created.
- No token is parsed as JWT for authorization correctness.
- No raw mutation becomes safe merely because `--yes` was supplied.

## Pilot Requirements

Before a production pilot, run the Windows-only ACL, ancestor-guard, executable/dependency-guard, process-tree Job Object, reparse, hard-link, bounded-growth/write-sharing, drive-classifier, and lock-sharing tests on a Windows x86_64 runner and independently verify the resulting descriptors on supported NTFS/ReFS configurations. Verify an actual mapped SMB drive in a managed Windows environment because the hosted runner test covers the `DRIVE_REMOTE` policy branch without provisioning a network mapping. Also verify cache ACLs on every target OS, proxy behavior, private-region service overrides, credential-process hardening, live tenant permissions/IP diagnostics, release provenance, and the synthetic dataset used for smoke tests.
