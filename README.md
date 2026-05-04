# VSXSentry Guard

A VS Code extension that auto-blocks and removes extensions listed in the
[VSXSentry](https://vsxsentry.github.io/) malicious & risky feeds.

**Source code:** [github.com/vsxsentry/vsxsentry-guard](https://github.com/vsxsentry/vsxsentry-guard)

On the VSCode Marketplace https://marketplace.visualstudio.com/items?itemName=mthcht.vsxsentry-guard

## Behaviour

- **Malicious feed** - enforced silently. Every installed extension whose ID matches
  the feed is uninstalled (or disabled / warned, per `vsxSentry.action`) on every
  check, regardless of severity or category. No prompt.
- **Risky feed** - opt-in (`vsxSentry.risky.enabled: true`). When enabled, matched
  extensions go through a QuickPick review where you can uncheck any you want to keep
  (e.g. you actually use Copilot or Remote-SSH). Kept IDs are remembered so you aren't
  re-prompted.

### Feed shape (May 2026 snapshot)

| Feed | Entries | Severities | Categories |
| --- | --- | --- | --- |
| malicious | 1,265 | critical 469, high 661, medium 120, low 15 | malware, impersonation, untrustworthy, spam, copyright-violation, owner-request, impersonation-malware, spam-malware |
| risky | 72 | high 14, medium 51, low 7 | high = Roo Code, Cline, Code Runner, Live Share, Remote-SSH, ngrok, Tailscale, Vault, etc. medium = Copilot, Tabnine, Continue, AWS Toolkit, Docker, Kubernetes, etc. |

The extension also writes blocked IDs into `extensions.allowed` so VS Code's own
install gate refuses future installs - using the documented `{ "*": true, "id": false }`
blocklist pattern, and merging safely with any existing user config.

## Limits

- There is no pre-install hook in the VS Code API, so this is **detect-and-uninstall**,
  not true prevention. A malicious extension can still run its `activate()` once before
  being removed. For real enforcement, deploy `extensions.allowed` as a system policy
  (Group Policy / `.mobileconfig` / `/etc/vscode/policy.json`).
- If `extensions.allowed` is policy-managed, the extension detects this and won't try
  to write - the policy is authoritative.
- A user (or another extension) can disable VSXSentry Guard. It's hygiene, not a
  security boundary.

## Configuration

| Setting | Default | Notes |
| --- | --- | --- |
| `vsxSentry.malicious.feedUrl` | VSXSentry malicious CSV | |
| `vsxSentry.risky.enabled` | `false` | Opt-in for risky feed |
| `vsxSentry.risky.feedUrl` | VSXSentry risky CSV | |
| `vsxSentry.risky.severities` | `["high"]` | Subset of `high`, `medium`, `low` |
| `vsxSentry.risky.categories` | `["*"]` | e.g. `["risky-tunnel", "risky-remote-access"]` |
| `vsxSentry.action` | `"remove"` | `remove` / `disable` / `warn` |
| `vsxSentry.applyToAllowedSetting` | `true` | Write to `extensions.allowed` |
| `vsxSentry.updateIntervalHours` | `6` | Background re-check interval |
| `vsxSentry.notifyOnNewEntries` | `true` | Toast when feed grows |

## Commands

- **VSXSentry: Check feeds now** - manual run
- **VSXSentry: Review pending entries** - same; surfaces the risky QuickPick
- **VSXSentry: Show last report** - webview with removed / kept / failed entries
- **VSXSentry: Clear user overrides** - forget which risky extensions you chose to keep

## Build

```bash
npm install
npm run compile
```

Then `F5` in VS Code (Extension Development Host) to run.
