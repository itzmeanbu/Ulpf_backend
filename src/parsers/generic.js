// Last-resort parser: accepts ANY plain-text log line (Linux auth.log,
// Apache/Nginx access logs, app logs, Windows text exports...) and pulls out
// what it can find: time, IP addresses, protocol and what kind of event it is.
// It always succeeds, so no uploaded line is rejected just for its format.

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const ISO_RE = /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/;
const APACHE_RE = /(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}:\d{2}:\d{2}) ([+-]\d{4})/;
const SYSLOG_TIME_RE = /\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b/;
const PROTO_RE = /\b(TCP|UDP|ICMP|HTTPS|HTTP|SSH|FTP|DNS|SMTP|RDP)\b/i;

function looksLikeGeneric(text) {
  return typeof text === 'string' && text.trim().length > 0;
}

function findTimestamp(line) {
  let m = line.match(ISO_RE);
  if (m) {
    const d = new Date(m[0].replace(' ', 'T'));
    if (!isNaN(d.getTime())) return d.toISOString();
  }
  m = line.match(APACHE_RE);
  if (m) {
    const d = new Date(`${m[1]} ${m[2]} ${m[3]} ${m[4]} ${m[5]}`);
    if (!isNaN(d.getTime())) return d.toISOString();
  }
  m = line.match(SYSLOG_TIME_RE);
  if (m) {
    const d = new Date(`${m[1]} ${m[2]} ${new Date().getFullYear()} ${m[3]}`);
    if (!isNaN(d.getTime())) return d.toISOString();
  }
  return new Date().toISOString();
}

function guessEventType(line) {
  if (/fail|invalid|unauthori[sz]ed|denied|refused|incorrect/i.test(line)) return 'auth-failure';
  if (/block|drop|reject|deny/i.test(line)) return 'blocked';
  if (/accept|success|allow|logged in|login/i.test(line)) return 'success';
  if (/error|critical|fatal|exception/i.test(line)) return 'error';
  if (/warn/i.test(line)) return 'warning';
  return 'text-log';
}

function parseGeneric(text) {
  const line = text.trim().split('\n')[0].trim();
  const ips = (line.match(IPV4_RE) || []).filter((ip) => ip.split('.').every((n) => Number(n) <= 255));
  const proto = line.match(PROTO_RE);

  return {
    vendor: 'generic-text',
    eventType: guessEventType(line),
    timestamp: findTimestamp(line),
    sourceIP: ips[0] || null,
    destIP: ips[1] || null,
    action: line.slice(0, 300),
    protocol: proto ? proto[1].toUpperCase() : null,
  };
}

module.exports = { looksLikeGeneric, parseGeneric };
