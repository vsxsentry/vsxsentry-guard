# VSXSentry Guard

A VS Code extension that auto-blocks and removes extensions listed in the
[VSXSentry](https://vsxsentry.github.io/) malicious & risky feeds.

**Source code:** [github.com/vsxsentry/vsxsentry-guard](https://github.com/vsxsentry/vsxsentry-guard)

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

## How protection works

VSXSentry Guard applies two layers of protection:

1. **Block at install time.** Every malicious extension ID from the feed is written
   to your `extensions.allowed` setting using the `{ "*": true, "id": false }` pattern.
   VS Code's own install gate then refuses to install any of those IDs - this is
   real prevention, enforced by VS Code itself. Already-installed matches are also
   disabled by VS Code as soon as the setting is written.
2. **Detect and uninstall at runtime.** On every check (startup, on-demand, every
   N hours, and on the `extensions.onDidChange` event), the extension walks every
   installed extension and uninstalls any that match the feed.

The two layers cover each other: the settings write prevents new installs even
when the extension isn't running, and the runtime check catches anything that
slipped in between feed updates.

## Edge cases worth knowing about

- **Brand-new threats not yet in the feed** are not blocked until the feed is
  updated and the extension re-checks (default: every 6 hours, configurable). For
  freshly-listed malware, there's a window between the feed update and your next
  check where a manual install could succeed; the extension will then uninstall
  it on the next check.
- **If `extensions.allowed` is managed by a system policy** (Group Policy on
  Windows, `.mobileconfig` on macOS, `/etc/vscode/policy.json` on Linux), the
  policy is authoritative and the extension won't try to write to the setting.
  The runtime detect-and-uninstall still works.
- **VS Code 1.96 is required** for the install-time block (when `extensions.allowed`
  was added). On older versions, only the runtime detect-and-uninstall layer is
  active.

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
