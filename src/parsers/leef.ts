// LEEF format:
// LEEF:Version|Vendor|Product|Version|EventID|key1=val1\tkey2=val2
import { ParsedFields } from '../types';

export function looksLikeLeef(line: string): boolean {
  return line.trim().startsWith('LEEF:');
}

export function parseLeef(line: string): ParsedFields | null {
  const body = line.trim().slice(5); // strip "LEEF:"
  const parts = body.split('|');
  if (parts.length < 5) return null;

  const [, vendor, product, , eventId] = parts;
  const attrString = parts.slice(5).join('|');
  const attrs: Record<string, string> = {};
  attrString.split(/\t|\s{2,}/).forEach((pair) => {
    const [k, v] = pair.split('=');
    if (k && v !== undefined) attrs[k.trim()] = v.trim();
  });

  return {
    vendor: vendor || 'unknown-leef',
    eventType: eventId || product || 'leef-event',
    timestamp: attrs.devTime || new Date().toISOString(),
    sourceIP: attrs.src || null,
    destIP: attrs.dst || null,
    action: attrs.cat || eventId || null,
    protocol: attrs.proto || null,
  };
}
