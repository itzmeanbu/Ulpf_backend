// Very small RFC3164-ish syslog parser, good enough for a prototype demo.
// Example line:
// <34>Oct 11 22:14:15 mymachine su: 'su root' failed for user on /dev/pts/8

const SYSLOG_RE = /^<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)$/;

function looksLikeSyslog(line) {
  return SYSLOG_RE.test(line.trim());
}

function parseSyslog(line) {
  const match = line.trim().match(SYSLOG_RE);
  if (!match) return null;
  const [, , timestampRaw, host, message] = match;

  return {
    vendor: 'generic-syslog',
    eventType: 'syslog',
    timestamp: safeDate(timestampRaw),
    sourceIP: host,
    destIP: null,
    action: message,
    protocol: null,
  };
}

function safeDate(str) {
  const d = new Date(`${str} ${new Date().getFullYear()}`);
  return isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

module.exports = { looksLikeSyslog, parseSyslog };
