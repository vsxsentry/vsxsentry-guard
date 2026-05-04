// src/extension.ts
import * as vscode from 'vscode';
import { fetchFeed, Feed } from './feed';
import {
  computeDecisions, applyAction, applyToAllowedSetting,
  readConfig, Decision
} from './enforcer';
import {
  reviewRiskyDecisions, showSummaryToast, showNewEntriesToast,
  renderReportHtml, emptyReport, Report
} from './ui';

const STATE_OVERRIDES = 'vsxSentry.userOverrides';   // string[] of ext ids the user opted to keep
const STATE_LAST_SEEN = 'vsxSentry.lastSeenIds';     // { malicious: string[], risky: string[] }
const STATE_LAST_REPORT = 'vsxSentry.lastReport';

interface LastSeen { malicious: string[]; risky: string[] }

let timer: NodeJS.Timeout | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const log = vscode.window.createOutputChannel('VSXSentry Guard');
  context.subscriptions.push(log);

  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 50);
  status.command = 'vsxSentry.checkNow';
  status.text = '$(shield) VSXSentry';
  status.tooltip = 'Click to run a feed check now';
  status.show();
  context.subscriptions.push(status);

  context.subscriptions.push(
    vscode.commands.registerCommand('vsxSentry.checkNow', () => runCheck(context, log, status, /*manual*/ true)),
    vscode.commands.registerCommand('vsxSentry.reviewPending', () => runCheck(context, log, status, true)),
    vscode.commands.registerCommand('vsxSentry.showReport', () => showLastReport(context)),
    vscode.commands.registerCommand('vsxSentry.clearOverrides', async () => {
      await context.globalState.update(STATE_OVERRIDES, []);
      vscode.window.showInformationMessage('VSXSentry: cleared user overrides.');
    })
  );

  // React to extensions being installed/uninstalled while VS Code is running.
  context.subscriptions.push(
    vscode.extensions.onDidChange(() => runCheck(context, log, status, false))
  );

  // Re-arm the timer whenever the interval changes.
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('vsxSentry.updateIntervalHours')) scheduleTimer(context, log, status);
    })
  );
  scheduleTimer(context, log, status);

  // Initial check on activation.
  runCheck(context, log, status, false).catch(err => log.appendLine(`activation error: ${err}`));
}

export function deactivate(): void {
  if (timer) clearInterval(timer);
}

function scheduleTimer(
  context: vscode.ExtensionContext,
  log: vscode.OutputChannel,
  status: vscode.StatusBarItem
): void {
  if (timer) clearInterval(timer);
  const hours = vscode.workspace.getConfiguration('vsxSentry').get<number>('updateIntervalHours', 6);
  const ms = Math.max(0.5, hours) * 3600 * 1000;
  timer = setInterval(() => {
    runCheck(context, log, status, false).catch(err => log.appendLine(`scheduled error: ${err}`));
  }, ms);
}

async function runCheck(
  context: vscode.ExtensionContext,
  log: vscode.OutputChannel,
  status: vscode.StatusBarItem,
  manual: boolean
): Promise<void> {
  const cfg = readConfig();
  const c = vscode.workspace.getConfiguration('vsxSentry');
  const maliciousUrl = c.get<string>('malicious.feedUrl')!;
  const riskyUrl    = c.get<string>('risky.feedUrl')!;
  const notify      = c.get<boolean>('notifyOnNewEntries', true);

  status.text = '$(sync~spin) VSXSentry';
  log.appendLine(`[${new Date().toISOString()}] running check (manual=${manual})`);

  let malicious: Feed;
  let risky: Feed | null = null;
  try {
    malicious = await fetchFeed(maliciousUrl, 'malicious');
    if (cfg.riskyEnabled) risky = await fetchFeed(riskyUrl, 'risky');
  } catch (err) {
    log.appendLine(`feed fetch failed: ${(err as Error).message}`);
    status.text = '$(shield) VSXSentry $(error)';
    status.tooltip = `Last fetch failed: ${(err as Error).message}`;
    if (manual) vscode.window.showErrorMessage(`VSXSentry: ${(err as Error).message}`);
    return;
  }

  // What's new since last run?
  const lastSeen: LastSeen = context.globalState.get(STATE_LAST_SEEN, { malicious: [], risky: [] });
  const lastMalSet = new Set(lastSeen.malicious);
  const lastRskSet = new Set(lastSeen.risky);
  const newMal = malicious.entries.filter(e => !lastMalSet.has(e.extensionId)).length;
  const newRsk = risky ? risky.entries.filter(e => !lastRskSet.has(e.extensionId)).length : 0;

  const overrides = new Set(context.globalState.get<string[]>(STATE_OVERRIDES, []));
  const decisions = computeDecisions(malicious, risky, cfg, overrides);

  const report = emptyReport();
  report.newSinceLastRun = { malicious: newMal, risky: newRsk };

  // Split malicious from risky.
  const malDecisions = decisions.filter(d => d.kind === 'malicious');
  const rskDecisions = decisions.filter(d => d.kind === 'risky');

  // Risky goes through user review (only if any matched). Malicious is silent.
  let riskyProceed: Decision[] = [];
  if (rskDecisions.length > 0) {
    const { proceed, keep } = await reviewRiskyDecisions(rskDecisions);
    riskyProceed = proceed;
    report.kept.push(...keep);
    // Remember keeps so we don't re-prompt next time.
    if (keep.length > 0) {
      const next = new Set(overrides);
      for (const d of keep) next.add(d.entry.extensionId);
      await context.globalState.update(STATE_OVERRIDES, [...next]);
    }
  }

  const toApply = [...malDecisions, ...riskyProceed];

  // Apply actions.
  for (const d of toApply) {
    try {
      await applyAction(d);
      if (d.action === 'remove')   report.removed.push(d);
      if (d.action === 'disable')  report.disabled.push(d);
      if (d.action === 'warn')     report.warnedOnly.push(d);
    } catch (err) {
      report.failed.push({ decision: d, error: (err as Error).message });
    }
  }

  // Write extensions.allowed (best-effort).
  if (cfg.applyToAllowedSetting) {
    const idsToBlock = malicious.entries.map(e => e.originalId);
    if (risky && cfg.riskyEnabled) {
      // Only persist user-acted-on risky ones; don't pre-block extensions
      // the user may legitimately want.
      idsToBlock.push(...riskyProceed.map(d => d.entry.originalId));
    }
    try {
      const r = await applyToAllowedSetting(idsToBlock);
      report.allowedSettingWritten = r.wrote;
      report.allowedSettingNote = r.reason;
    } catch (err) {
      report.allowedSettingNote = `update failed: ${(err as Error).message}`;
      log.appendLine(report.allowedSettingNote);
    }
  }

  // Persist last-seen IDs and last report.
  await context.globalState.update(STATE_LAST_SEEN, {
    malicious: malicious.entries.map(e => e.extensionId),
    risky: risky ? risky.entries.map(e => e.extensionId) : lastSeen.risky
  } satisfies LastSeen);
  await context.globalState.update(STATE_LAST_REPORT, report);

  // Status bar + notifications.
  const total = report.removed.length + report.disabled.length + report.warnedOnly.length + report.failed.length;
  status.text = total > 0 ? `$(shield) VSXSentry $(warning) ${total}` : '$(shield) VSXSentry';
  status.tooltip = total > 0 ? `${total} action(s) at last run - click to re-check` : 'No threats - click to re-check';

  if (notify && (newMal > 0 || newRsk > 0)) showNewEntriesToast({ malicious: newMal, risky: newRsk }, cfg.riskyEnabled);
  if (manual || total > 0) showSummaryToast(report);

  log.appendLine(`done: removed=${report.removed.length} disabled=${report.disabled.length} warned=${report.warnedOnly.length} kept=${report.kept.length} failed=${report.failed.length}`);
}

async function showLastReport(context: vscode.ExtensionContext): Promise<void> {
  const report = context.globalState.get<Report>(STATE_LAST_REPORT);
  if (!report) {
    vscode.window.showInformationMessage('VSXSentry: no report yet - run a check first.');
    return;
  }
  const cfg = readConfig();
  const c = vscode.workspace.getConfiguration('vsxSentry');
  let malicious: Feed, risky: Feed | null = null;
  try {
    malicious = await fetchFeed(c.get<string>('malicious.feedUrl')!, 'malicious');
    if (cfg.riskyEnabled) risky = await fetchFeed(c.get<string>('risky.feedUrl')!, 'risky');
  } catch {
    // Show report without feed counts if we can't fetch.
    malicious = { kind: 'malicious', fetchedAt: 0, entries: [], byId: new Map() };
  }
  const panel = vscode.window.createWebviewPanel(
    'vsxSentryReport', 'VSXSentry Report', vscode.ViewColumn.Active, {}
  );
  panel.webview.html = renderReportHtml(report, malicious, risky);
}
