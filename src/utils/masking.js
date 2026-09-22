// Rule/regex based masking. This is the FIRST security layer and it never
// depends on AI - AI may only ever supplement it, never replace it.

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const PHONE_RE = /\b(\+?\d{1,3}[- ]?)?\(?\d{3,4}\)?[- ]?\d{3,4}[- ]?\d{3,4}\b/g;
const API_KEY_RE = /\b(?:key|token|apikey|api_key|secret)[=:]\s*[A-Za-z0-9\-_]{8,}/gi;
const PASSWORD_RE = /\b(?:pass|password|pwd)[=:]\s*\S+/gi;

function maskEmail(str) {
  return str.replace(EMAIL_RE, (m) => {
    const [user, domain] = m.split('@');
    return `${user.slice(0, 2)}****@${domain}`;
  });
}

function maskPhone(str) {
  return str.replace(PHONE_RE, (m) => m.slice(0, 2) + '*'.repeat(Math.max(m.length - 2, 3)));
}

function maskApiKey(str) {
  return str.replace(API_KEY_RE, (m) => m.split(/[=:]/)[0] + '=****REDACTED****');
}

function maskPassword(str) {
  return str.replace(PASSWORD_RE, (m) => m.split(/[=:]/)[0] + '=****REDACTED****');
}

// Masks an IPv4 address, keeping the network portion and hiding the host
// portion, e.g. 192.168.1.20 -> 192.168.xxx.xxx
function maskIp(ip) {
  if (!ip) return ip;
  const parts = ip.split('.');
  if (parts.length !== 4) return ip;
  return `${parts[0]}.${parts[1]}.xxx.xxx`;
}

// Runs every text-based rule over a raw string (used on free-text fields
// like the raw log line before it's shown to a non-approved user).
function maskFreeText(text) {
  if (!text) return text;
  let out = text;
  out = maskEmail(out);
  out = maskPhone(out);
  out = maskApiKey(out);
  out = maskPassword(out);
  return out;
}

// Produces the masked version of a normalized event object. IP fields get
// the IP-specific mask; any other string field runs through the free-text
// rules so nothing sensitive slips through in an unexpected field.
function maskNormalizedEvent(event) {
  const masked = { ...event };
  if (masked.sourceIP) masked.sourceIP = maskIp(masked.sourceIP);
  if (masked.destIP) masked.destIP = maskIp(masked.destIP);
  for (const field of ['action', 'vendor', 'eventType', 'protocol']) {
    if (typeof masked[field] === 'string') {
      masked[field] = maskFreeText(masked[field]);
    }
  }
  masked.masked = true;
  return masked;
}

module.exports = { maskFreeText, maskIp, maskNormalizedEvent };
