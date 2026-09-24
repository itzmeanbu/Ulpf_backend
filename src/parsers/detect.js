const { looksLikeJson, parseJson } = require('./json');
const { looksLikeCef, parseCef } = require('./cef');
const { looksLikeLeef, parseLeef } = require('./leef');
const { looksLikeSyslog, parseSyslog } = require('./syslog');
const { looksLikeCsv, parseCsv } = require('./csv');
const { looksLikeGeneric, parseGeneric } = require('./generic');

// New vendor formats get added here as one more { name, test, parse } entry
// - the rest of the system never has to change.
const PARSERS = [
  { name: 'json', test: looksLikeJson, parse: parseJson },
  { name: 'cef', test: looksLikeCef, parse: parseCef },
  { name: 'leef', test: looksLikeLeef, parse: parseLeef },
  { name: 'syslog', test: looksLikeSyslog, parse: parseSyslog },
  { name: 'csv', test: looksLikeCsv, parse: parseCsv },
  // Always last: catches any plain-text log line the formats above did not.
  { name: 'text', test: looksLikeGeneric, parse: parseGeneric },
];

// Returns { formatName, fields } or null if nothing matched.
function detectAndParse(rawLog) {
  for (const parser of PARSERS) {
    if (parser.test(rawLog)) {
      const fields = parser.parse(rawLog);
      if (fields) return { formatName: parser.name, fields };
    }
  }
  return null;
}

module.exports = { detectAndParse };
