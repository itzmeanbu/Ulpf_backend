// Small syslog parser. Understands both forms:
//   <34>Oct 11 22:14:15 mymachine su: 'su root' failed for user on /dev/pts/8
//   Oct 11 22:14:15 mymachine sshd[812]: Failed password for root from 10.0.0.9
// (the <34> priority part is optional, so normal Linux auth.log lines work)

const SYSLOG_RE = /^(?:<(\d+)>)?([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$/;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

function looksLikeSyslog(line) {
  return SYSLOG_RE.test(line.trim());
}

function parseSyslog(line) {
  const match = line.trim().match(SYSLOG_RE);
  if (!match) return null;
  const [, , timestampRaw, host, message] = match;

  // If the message names an IP (like a failed login "from 1.2.3.4"), that is
  // the useful source address; otherwise fall back to the host name.
  const ipInMessage = message.match(IPV4_RE);

  return {
    vendor: 'generic-syslog',
    eventType: 'syslog',
    timestamp: safeDate(timestampRaw),
    sourceIP: ipInMessage ? ipInMessage[0] : host,
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
