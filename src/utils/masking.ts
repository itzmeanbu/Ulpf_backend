// Rule/regex based masking. This is the FIRST security layer and it never
// depends on AI - AI may only ever supplement it, never replace it.
import { MaskingConfig, NormalizedEvent } from '../types';

const EMAIL_RE = /[a-zA-Z0-9._%+*-]+@[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}/g;
const IP_IN_TEXT_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const PHONE_RE = /\b(\+?\d{1,3}[- ]?)?\(?\d{3,4}\)?[- ]?\d{3,4}[- ]?\d{3,4}\b/g;
const API_KEY_RE = /\b(?:key|token|apikey|api_key|secret)[=:]\s*[A-Za-z0-9\-_]{8,}/gi;
const PASSWORD_RE = /\b(?:pass|password|pwd)[=:]\s*\S+/gi;

export const DEFAULT_MASKING_CONFIG: MaskingConfig = {
  email: true,
  password: true,
  apiKey: true,
  phone: true,
  ip: true,
};

function maskEmail(str: string): string {
  return str.replace(EMAIL_RE, (m) => {
    const at = m.lastIndexOf('@');
    const user = m.slice(0, at);
    const tld = m.slice(m.lastIndexOf('.') + 1);
    return `${user.replace(/\*/g, '').slice(0, 1) || '*'}****@****.${tld}`;
  });
}

function maskIpsInText(str: string): string {
  return str.replace(IP_IN_TEXT_RE, (ip) => maskIp(ip));
}

function maskPhone(str: string): string {
  const hide = (m: string) => m.slice(0, 2) + '*'.repeat(Math.max(m.length - 2, 3));
  return str
    .replace(PHONE_RE, hide)
    .replace(/(?:\+\d{1,3}[- ])?\b\d{5}[- ]\d{5}\b/g, hide);
}

function maskApiKey(str: string): string {
  return str.replace(API_KEY_RE, (m) => m.split(/[=:]/)[0] + '=****REDACTED****');
}

function maskPassword(str: string): string {
  return str.replace(PASSWORD_RE, (m) => m.split(/[=:]/)[0] + '=****REDACTED****');
}

export function maskIp(ip: string | null | undefined): any {
  if (!ip) return ip;
  const parts = ip.split('.');
  if (parts.length !== 4) return ip;
  return `${parts[0]}.${parts[1]}.xxx.xxx`;
}

export function maskFreeText(text: string | null | undefined, config: MaskingConfig = DEFAULT_MASKING_CONFIG): any {
  if (!text) return text;
  let out = text;
  if (config.ip !== false) out = maskIpsInText(out);
  if (config.email !== false) out = maskEmail(out);
  if (config.phone !== false) out = maskPhone(out);
  if (config.apiKey !== false) out = maskApiKey(out);
  if (config.password !== false) out = maskPassword(out);
  return out;
}

export function maskNormalizedEvent(event: NormalizedEvent, config: MaskingConfig = DEFAULT_MASKING_CONFIG): NormalizedEvent {
  const masked: NormalizedEvent = { ...event };
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
