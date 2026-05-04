// src/feed.ts
//
// Fetch and parse the VSXSentry CSV feeds. The feed has fields that contain
// commas inside quoted strings (e.g. "microsoft_removed_packages,static_list"),
// so we need a real RFC 4180 parser, not a naive split.

export interface FeedEntry {
  extensionId: string;        // canonical "publisher.name", lowercased for matching
  originalId: string;         // original casing as it appears in the feed
  publisherId: string;
  extensionName: string;
  comment: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  category: string;
  source: string;
  reference: string;
  status: string;
  removalDate: string;
}

export type FeedKind = 'malicious' | 'risky';

export interface Feed {
  kind: FeedKind;
  fetchedAt: number;
  entries: FeedEntry[];
  byId: Map<string, FeedEntry>; // keyed on lowercase extensionId
}

/** Minimal RFC 4180 CSV parser. Handles quoted fields with embedded commas, "" escaping, and CRLF. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  let i = 0;

  while (i < text.length) {
    const ch = text[i];

    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      field += ch;
      i++;
      continue;
    }

    if (ch === '"') { inQuotes = true; i++; continue; }
    if (ch === ',') { row.push(field); field = ''; i++; continue; }
    if (ch === '\r') { i++; continue; }
    if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
      i++;
      continue;
    }
    field += ch;
    i++;
  }

  // Final field/row if no trailing newline
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function rowToEntry(headers: string[], row: string[]): FeedEntry | null {
  const get = (name: string) => {
    const idx = headers.indexOf(name);
    return idx >= 0 ? (row[idx] ?? '') : '';
  };
  const originalId = get('extension_id').trim();
  if (!originalId) return null;
  return {
    extensionId: originalId.toLowerCase(),
    originalId,
    publisherId:   get('publisher_id'),
    extensionName: get('extension_name'),
    comment:       get('metadata_comment'),
    severity:      get('metadata_severity').toLowerCase(),
    category:      get('metadata_category'),
    source:        get('metadata_source'),
    reference:     get('metadata_reference'),
    status:        get('metadata_status'),
    removalDate:   get('removal_date')
  };
}

export async function fetchFeed(url: string, kind: FeedKind, signal?: AbortSignal): Promise<Feed> {
  // Node 18+ ships fetch globally; VS Code 1.82+ uses Node 18.
  const res = await fetch(url, { signal });
  if (!res.ok) throw new Error(`Feed fetch failed (${kind}): ${res.status} ${res.statusText}`);
  const text = await res.text();

  const rows = parseCsv(text).filter(r => r.some(cell => cell.length > 0));
  if (rows.length === 0) throw new Error(`Feed ${kind} is empty`);

  const headers = rows[0].map(h => h.trim());
  const entries: FeedEntry[] = [];
  for (let i = 1; i < rows.length; i++) {
    const e = rowToEntry(headers, rows[i]);
    if (e) entries.push(e);
  }

  const byId = new Map<string, FeedEntry>();
  for (const e of entries) byId.set(e.extensionId, e);

  return { kind, fetchedAt: Date.now(), entries, byId };
}
