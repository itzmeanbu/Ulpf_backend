// Expects a header row on first line, e.g.:
// timestamp,src_ip,dst_ip,action,protocol,vendor,event_type
import { ParsedFields } from '../types';

export function looksLikeCsv(text: string): boolean {
  const firstLine = text.trim().split('\n')[0] || '';
  return firstLine.includes(',') && !firstLine.startsWith('{') && !firstLine.startsWith('CEF:') && !firstLine.startsWith('LEEF:');
}

export function parseCsv(text: string): ParsedFields | null {
  const lines = text.trim().split('\n');
  if (lines.length < 2) return null;

  const headers = lines[0].split(',').map((h) => h.trim().toLowerCase());
  const values = lines[1].split(',').map((v) => v.trim());
  const row: Record<string, string> = {};
  headers.forEach((h, i) => (row[h] = values[i]));

  return {
    vendor: row.vendor || 'unknown-csv',
    eventType: row.event_type || row.eventtype || 'csv-event',
    timestamp: row.timestamp || new Date().toISOString(),
    sourceIP: row.src_ip || row.source_ip || row.sourceip || null,
    destIP: row.dst_ip || row.dest_ip || row.destip || null,
    action: row.action || null,
    protocol: row.protocol || null,
  };
}
