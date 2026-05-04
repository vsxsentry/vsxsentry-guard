// src/enforcer.ts
//
// Core enforcement: given the two parsed feeds, decide what to do for each
// installed extension and (optionally) write blocked IDs into extensions.allowed.

import * as vscode from 'vscode';
import { Feed, FeedEntry, FeedKind } from './feed';

/** Identifier of this extension itself, so we never act on ourselves. */
export const SELF_ID = 'mthcht.vsxsentry-guard';

export type Action = 'remove' | 'disable' | 'warn';

export interface Decision {
  entry: FeedEntry;
  kind: FeedKind;
  installed: boolean;
  action: Action;
  reason: string;
}

export interface Config {
  riskyEnabled: boolean;
  riskySeverities: Set<string>;
  riskyCategories: Set<string>; // may contain '*'
  action: Action;
  applyToAllowedSetting: boolean;
}

export function readConfig(): Config {
  const c = vscode.workspace.getConfiguration('vsxSentry');
  return {
    riskyEnabled:    c.get<boolean>('risky.enabled', false),
    riskySeverities: new Set((c.get<string[]>('risky.severities', ['high'])).map(s => s.toLowerCase())),
    riskyCategories: new Set(c.get<string[]>('risky.categories', ['*'])),
    action:          c.get<Action>('action', 'remove'),
    applyToAllowedSetting: c.get<boolean>('applyToAllowedSetting', true)
  };
}

/** Filter risky entries by user-configured severity & category. */
function riskyMatches(entry: FeedEntry, cfg: Config): boolean {
  if (!cfg.riskySeverities.has(entry.severity)) return false;
  if (cfg.riskyCategories.has('*')) return true;
  // category field can be a single value; match plainly
  return cfg.riskyCategories.has(entry.category);
}

/**
 * Compute decisions for every installed extension that appears in either feed.
 * Malicious matches always get the configured action with no further filtering.
 * Risky matches only show up when the user opted in AND severity/category match.
 */
export function computeDecisions(
  malicious: Feed,
  risky: Feed | null,
  cfg: Config,
  userOverrides: Set<string>
): Decision[] {
  const decisions: Decision[] = [];
  for (const ext of vscode.extensions.all) {
    const id = ext.id.toLowerCase();
    if (id === SELF_ID.toLowerCase()) continue;

    const malHit = malicious.byId.get(id);
    if (malHit) {
      decisions.push({
        entry: malHit,
        kind: 'malicious',
        installed: true,
        action: cfg.action,
        reason: malHit.comment || 'listed in malicious feed'
      });
      continue; // malicious wins over risky
    }

    if (cfg.riskyEnabled && risky) {
      const riskHit = risky.byId.get(id);
      if (riskHit && riskyMatches(riskHit, cfg) && !userOverrides.has(id)) {
        decisions.push({
          entry: riskHit,
          kind: 'risky',
          installed: true,
          action: cfg.action,
          reason: riskHit.comment || 'listed in risky feed'
        });
      }
    }
  }
  return decisions;
}

/** Execute the action (uninstall / disable / warn) for a single decision. */
export async function applyAction(d: Decision): Promise<void> {
  const id = d.entry.originalId; // VS Code accepts the canonical-cased id
  if (d.action === 'warn') return;
  try {
    if (d.action === 'remove') {
      await vscode.commands.executeCommand('workbench.extensions.uninstallExtension', id);
    } else if (d.action === 'disable') {
      await vscode.commands.executeCommand('workbench.extensions.disableExtension', id);
    }
  } catch (err) {
    // The command may fail if the extension is already uninstalled or VS Code
    // can't act on it. Surface the error to the caller via re-throw so the UI
    // layer can record it in the report.
    throw new Error(`Failed to ${d.action} ${id}: ${(err as Error).message}`);
  }
}

/**
 * Merge blocked IDs into the user's `extensions.allowed` setting.
 *
 * Safety rules:
 *  - If the setting is policy-managed → don't touch it; the policy is authoritative.
 *  - If the user already has an allowlist (no "*" key, or "*": false) → don't add a
 *    "*": true wildcard, because that would silently flip their allowlist to a blocklist.
 *    We only add explicit `false` entries; on an allowlist they're already blocked.
 *  - Otherwise → ensure "*": true is present (default-allow) and add `false` for each
 *    blocked ID. Preserve all other existing entries verbatim.
 *
 * Writes only at Global target.
 */
export async function applyToAllowedSetting(
  blockedIds: string[]      // original-cased ids
): Promise<{ wrote: boolean; reason?: string }> {
  if (blockedIds.length === 0) return { wrote: false, reason: 'nothing to block' };

  const inspect = vscode.workspace.getConfiguration('extensions').inspect('allowed');
  // Detect any policy presence - VS Code exposes policyValue on inspect() results.
  const policyValue = (inspect as any)?.policyValue;
  if (policyValue !== undefined) {
    return { wrote: false, reason: 'extensions.allowed is managed by system policy' };
  }

  const existing = (inspect?.globalValue as Record<string, unknown> | undefined) ?? {};
  const merged: Record<string, unknown> = { ...existing };

  const hasStar = Object.prototype.hasOwnProperty.call(merged, '*');
  const userIsAllowlistMode =
    (hasStar && merged['*'] === false) ||
    (!hasStar && Object.keys(merged).length > 0); // only positive entries → allowlist

  if (!userIsAllowlistMode) {
    if (!hasStar) merged['*'] = true; // default-allow blocklist mode
    for (const id of blockedIds) merged[id] = false;
  } else {
    // Don't touch their allowlist semantics; only add explicit false entries.
    // On an allowlist these are doubly-blocked, which is fine.
    for (const id of blockedIds) merged[id] = false;
  }

  await vscode.workspace.getConfiguration('extensions')
    .update('allowed', merged, vscode.ConfigurationTarget.Global);
  return { wrote: true };
}
