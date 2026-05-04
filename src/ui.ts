// src/ui.ts
import * as vscode from 'vscode';
import { Decision } from './enforcer';
import { Feed } from './feed';

export interface Report {
  ranAt: number;
  removed: Decision[];
  disabled: Decision[];
  warnedOnly: Decision[];
  kept: Decision[];          // user chose to keep this risky one
  failed: { decision: Decision; error: string }[];
  newSinceLastRun: { malicious: number; risky: number };
  allowedSettingWritten: boolean;
  allowedSettingNote?: string;
}

export function emptyReport(): Report {
  return {
    ranAt: Date.now(),
    removed: [], disabled: [], warnedOnly: [], kept: [], failed: [],
    newSinceLastRun: { malicious: 0, risky: 0 },
    allowedSettingWritten: false
  };
}

/**
 * Ask the user which risky decisions to apply. Returns the kept-as-is set
 * (so we can persist user overrides) and the proceed set.
 */
export async function reviewRiskyDecisions(
  riskyDecisions: Decision[]
): Promise<{ proceed: Decision[]; keep: Decision[] }> {
  if (riskyDecisions.length === 0) return { proceed: [], keep: [] };

  const items = riskyDecisions.map(d => ({
    label: `$(warning) ${d.entry.originalId}`,
    description: d.entry.severity,
    detail: d.reason,
    picked: true,
    decision: d
  }));

  const picked = await vscode.window.showQuickPick(items, {
    canPickMany: true,
    title: 'VSXSentry - risky extensions detected',
    placeHolder: 'Uncheck any you want to keep. Kept extensions are remembered.'
  });

  if (!picked) {
    // User dismissed → keep everything for now, don't persist
    return { proceed: [], keep: [] };
  }

  const proceedSet = new Set(picked.map(p => p.decision.entry.extensionId));
  const proceed: Decision[] = [];
  const keep: Decision[] = [];
  for (const d of riskyDecisions) {
    if (proceedSet.has(d.entry.extensionId)) proceed.push(d);
    else keep.push(d);
  }
  return { proceed, keep };
}

export function showSummaryToast(r: Report): void {
  const parts: string[] = [];
  if (r.removed.length)    parts.push(`removed ${r.removed.length}`);
  if (r.disabled.length)   parts.push(`disabled ${r.disabled.length}`);
  if (r.warnedOnly.length) parts.push(`flagged ${r.warnedOnly.length}`);
  if (r.kept.length)       parts.push(`kept ${r.kept.length}`);
  if (r.failed.length)     parts.push(`failed ${r.failed.length}`);
  if (parts.length === 0) return;

  const msg = `VSXSentry: ${parts.join(', ')}.`;
  if (r.failed.length > 0) {
    vscode.window.showWarningMessage(msg, 'Show report')
      .then(c => { if (c) vscode.commands.executeCommand('vsxSentry.showReport'); });
  } else {
    vscode.window.showInformationMessage(msg, 'Show report')
      .then(c => { if (c) vscode.commands.executeCommand('vsxSentry.showReport'); });
  }
}

export function showNewEntriesToast(
  newCount: { malicious: number; risky: number },
  riskyEnabled: boolean
): void {
  if (newCount.malicious === 0 && (newCount.risky === 0 || !riskyEnabled)) return;
  const bits: string[] = [];
  if (newCount.malicious > 0) bits.push(`${newCount.malicious} new malicious`);
  if (riskyEnabled && newCount.risky > 0) bits.push(`${newCount.risky} new risky`);
  vscode.window.showInformationMessage(
    `VSXSentry feeds updated: ${bits.join(', ')}.`,
    'Run check now'
  ).then(c => { if (c) vscode.commands.executeCommand('vsxSentry.checkNow'); });
}

export function renderReportHtml(r: Report, malicious: Feed, risky: Feed | null): string {
  const fmt = (ds: Decision[]) =>
    ds.length === 0
      ? '<p><em>none</em></p>'
      : '<ul>' + ds.map(d =>
          `<li><code>${escapeHtml(d.entry.originalId)}</code> - ${escapeHtml(d.reason)} <span class="sev">(${escapeHtml(d.entry.severity)})</span></li>`
        ).join('') + '</ul>';

  const fmtFailed = (fs: Report['failed']) =>
    fs.length === 0
      ? '<p><em>none</em></p>'
      : '<ul>' + fs.map(f =>
          `<li><code>${escapeHtml(f.decision.entry.originalId)}</code> - ${escapeHtml(f.error)}</li>`
        ).join('') + '</ul>';

  return `<!doctype html><html><head><meta charset="utf-8"><style>
    body { font-family: var(--vscode-font-family); padding: 16px; }
    h2 { margin-top: 24px; }
    code { background: var(--vscode-textBlockQuote-background); padding: 1px 4px; border-radius: 3px; }
    .sev { opacity: 0.7; font-size: 90%; }
    .meta { opacity: 0.7; font-size: 90%; margin-bottom: 16px; }
  </style></head><body>
    <h1>VSXSentry report</h1>
    <p class="meta">
      Run at ${new Date(r.ranAt).toLocaleString()}.
      Malicious feed: ${malicious.entries.length} entries.
      Risky feed: ${risky ? risky.entries.length + ' entries' : 'disabled'}.
      ${r.allowedSettingWritten ? 'extensions.allowed updated.' : (r.allowedSettingNote ? 'extensions.allowed not written: ' + escapeHtml(r.allowedSettingNote) : '')}
    </p>
    <h2>Removed (${r.removed.length})</h2>${fmt(r.removed)}
    <h2>Disabled (${r.disabled.length})</h2>${fmt(r.disabled)}
    <h2>Flagged only (${r.warnedOnly.length})</h2>${fmt(r.warnedOnly)}
    <h2>Kept by user (${r.kept.length})</h2>${fmt(r.kept)}
    <h2>Failed (${r.failed.length})</h2>${fmtFailed(r.failed)}
  </body></html>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]!));
}
