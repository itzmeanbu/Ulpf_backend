import { looksLikeJson, parseJson } from './json';
import { looksLikeCef, parseCef } from './cef';
import { looksLikeLeef, parseLeef } from './leef';
import { looksLikeSyslog, parseSyslog } from './syslog';
import { looksLikeCsv, parseCsv } from './csv';
import { looksLikeGeneric, parseGeneric } from './generic';
import { ParsedFields } from '../types';

interface ParserDef {
  name: string;
  test: (text: string) => boolean;
  parse: (text: string) => ParsedFields | null;
}

// New vendor formats get added here as one more { name, test, parse } entry
// - the rest of the system never has to change.
const PARSERS: ParserDef[] = [
  { name: 'json', test: looksLikeJson, parse: parseJson },
  { name: 'cef', test: looksLikeCef, parse: parseCef },
  { name: 'leef', test: looksLikeLeef, parse: parseLeef },
  { name: 'syslog', test: looksLikeSyslog, parse: parseSyslog },
  { name: 'csv', test: looksLikeCsv, parse: parseCsv },
  // Always last: catches any plain-text log line the formats above did not.
  { name: 'text', test: looksLikeGeneric, parse: parseGeneric },
];

export interface DetectResult {
  formatName: string;
  fields: ParsedFields;
}

// Returns { formatName, fields } or null if nothing matched.
export function detectAndParse(rawLog: string): DetectResult | null {
  for (const parser of PARSERS) {
    if (parser.test(rawLog)) {
      const fields = parser.parse(rawLog);
      if (fields) return { formatName: parser.name, fields };
    }
  }
  return null;
}
