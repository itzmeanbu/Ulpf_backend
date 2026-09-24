// Rule/regex based masking. This is the FIRST security layer and it never
// depends on AI - AI may only ever supplement it, never replace it.

const EMAIL_RE = /[a-zA-Z0-9._%+*-]+@[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}/g;
// Any IPv4 address written inside free text (like "from 203.0.113.9 port 22").
const IP_IN_TEXT_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const PHONE_RE = /\b(\+?\d{1,3}[- ]?)?\(?\d{3,4}\)?[- ]?\d{3,4}[- ]?\d{3,4}\b/g;
const API_KEY_RE = /\b(?:key|token|apikey|api_key|secret)[=:]\s*[A-Za-z0-9\-_]{8,}/gi;
const PASSWORD_RE = /\b(?:pass|password|pwd)[=:]\s*\S+/gi;

// NEW: every field an admin can flip on/off from the Masking Rules screen.
// Kept "on" if a key is missing so nothing is accidentally left unmasked.
const DEFAULT_MASKING_CONFIG = {
  email: true,
  password: true,
  apiKey: true,
  phone: true,
  ip: true,
};

// ad@example.com -> a****@****.com  (hides the name AND the company domain)
function maskEmail(str) {
  return str.replace(EMAIL_RE, (m) => {
    const at = m.lastIndexOf('@');
    const user = m.slice(0, at);
    const tld = m.slice(m.lastIndexOf('.') + 1);
    return `${user.replace(/\*/g, '').slice(0, 1) || '*'}****@****.${tld}`;
  });
}

// IPs inside text: 203.0.113.9 -> 203.0.xxx.xxx
function maskIpsInText(str) {
  return str.replace(IP_IN_TEXT_RE, (ip) => maskIp(ip));
}

function maskPhone(str) {
  const hide = (m) => m.slice(0, 2) + '*'.repeat(Math.max(m.length - 2, 3));
  return str
    .replace(PHONE_RE, hide)
    // 10-digit mobile numbers written as 5+5 (e.g. 98765 43210)
    .replace(/(?:\+\d{1,3}[- ])?\b\d{5}[- ]\d{5}\b/g, hide);
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

// Runs the text-based rules that are turned on over a raw string (used on
// free-text fields like the raw log line before it's shown to a non-approved
// user). `config` comes from the admin Masking Rules screen.
function maskFreeText(text, config = DEFAULT_MASKING_CONFIG) {
  if (!text) return text;
  let out = text;
  if (config.ip !== false) out = maskIpsInText(out);
  if (config.email !== false) out = maskEmail(out);
  if (config.phone !== false) out = maskPhone(out);
  if (config.apiKey !== false) out = maskApiKey(out);
  if (config.password !== false) out = maskPassword(out);
  return out;
}

// Produces the masked version of a normalized event object. IP fields get
// the IP-specific mask (unless turned off); any other string field runs
// through the free-text rules so nothing sensitive slips through in an
// unexpected field. `config` is the admin-configured on/off map; if it's
// not supplied every rule defaults to on, same as before this change.
function maskNormalizedEvent(event, config = DEFAULT_MASKING_CONFIG) {
  const masked = { ...event };
  if (config.ip !== false) {
    if (masked.sourceIP) masked.sourceIP = maskIp(masked.sourceIP);
    if (masked.destIP) masked.destIP = maskIp(masked.destIP);
  }
  for (const field of ['action', 'vendor', 'eventType', 'protocol']) {
    if (typeof masked[field] === 'string') {
      masked[field] = maskFreeText(masked[field], config);
    }
  }
  masked.masked = true;
  return masked;
}

module.exports = { maskFreeText, maskIp, maskNormalizedEvent, DEFAULT_MASKING_CONFIG };
