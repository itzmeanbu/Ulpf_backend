// Turns a normalized (or masked) log event into ONE plain-English sentence,
// e.g. "Cisco ASA blocked a TCP connection from 192.168.xxx.xxx to
// 10.0.xxx.xxx." This is what powers the "readable" part of ULPF.
//
// Two things happen, in order:
//  1. translateCommonTerms() - a small offline dictionary swaps common
//     security words (denied/blocked/failed/etc.) found written in Spanish,
//     French, German, Portuguese or Italian into English. No API key, no
//     network call - works the same locally and on Render.
//  2. buildReadableSummary() - turns the (now English) fields into a single
//     natural sentence instead of raw field:value pairs.
//
// IMPORTANT LIMITATION: this is a keyword translator, not a full translation
// engine. It only recognizes the security-relevant words listed below - if a
// vendor logs entire sentences in another language, only those words get
// swapped and the rest passes through unchanged. Wiring in a real
// translation API (DeepL / Google Translate) would replace step 1 with an
// actual API call and needs its own API key - ask if you want that added.

const TERM_MAP = [
  // [pattern (case-insensitive), English replacement]
  [/denegad[oa]|negad[oa]/gi, 'denied'],
  [/rechazad[oa]|refus(?:é|ée)/gi, 'rejected'],
  [/bloqueé|bloqu(?:é|ée)|bloqueado|blockiert|bloccato/gi, 'blocked'],
  [/permitid[oa]|autoris(?:é|ée)|erlaubt|consentito/gi, 'allowed'],
  [/acept(?:ado|ada|é|ée)|akzeptiert|accettato|aceito/gi, 'accepted'],
  [/fallid[oa]|fallo|échec|fehlgeschlagen|falha|fallito/gi, 'failed'],
  [/conexi(?:ó|o)n|connexion|verbindung|conex(?:ã|a)o|connessione/gi, 'connection'],
  [/contrase(?:ñ|n)a|mot de passe|passwort|senha|password/gi, 'password'],
  [/inicio de sesi(?:ó|o)n|anmeldung|accesso/gi, 'login'],
  [/usuario|utilisateur|benutzer|utente/gi, 'user'],
  [/error|erreur|fehler|errore/gi, 'error'],
  [/advertencia|avertissement|warnung|avviso/gi, 'warning'],
];

function translateCommonTerms(text) {
  if (!text || typeof text !== 'string') return text;
  let out = text;
  for (const [pattern, replacement] of TERM_MAP) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

function classifyVerb(actionText, eventType) {
  const t = `${actionText || ''} ${eventType || ''}`.toLowerCase();
  if (/deny|denied|block|blocked|drop|reject|refus/.test(t)) return 'blocked';
  if (/fail|invalid|unauthori[sz]ed|incorrect|auth-failure/.test(t)) return 'flagged a failed attempt on';
  if (/error|critical|fatal|exception/.test(t)) return 'hit an error during';
  if (/warn/.test(t)) return 'raised a warning during';
  if (/allow|accept|permit|success|logged in|login/.test(t)) return 'allowed';
  return 'logged';
}

// Builds one plain-English sentence from a normalized/masked event object.
// Works on either the masked view or the decrypted/unmasked view - both
// have the same field shape (vendor, eventType, action, protocol,
// sourceIP, destIP).
function buildReadableSummary(event) {
  if (!event) return 'No details available for this log.';

  const vendor = event.vendor && !/^unknown/i.test(event.vendor) ? event.vendor : 'An unknown source';
  const translatedAction = translateCommonTerms(event.action);
  const verb = classifyVerb(translatedAction, event.eventType);

  const proto = event.protocol ? `${event.protocol} ` : '';
  const hasEndpoints = event.sourceIP || event.destIP;
  let where = '';
  if (hasEndpoints) {
    where = ` ${proto}traffic`;
    if (event.sourceIP) where += ` from ${event.sourceIP}`;
    if (event.destIP) where += ` to ${event.destIP}`;
  }

  let sentence = `${vendor} ${verb}${where}.`;

  // A short action code (1-2 words, e.g. "denied", "Firewall Deny") is
  // already captured by the verb above, so repeating it would be noise.
  // Anything longer is an actual message - syslog/generic parsers put the
  // whole free-text line in `action` - and is worth showing in full,
  // regardless of whether IPs were also found.
  const wordCount = translatedAction ? translatedAction.trim().split(/\s+/).length : 0;
  if (wordCount > 2) {
    const detail = translatedAction.length > 200 ? `${translatedAction.slice(0, 200)}...` : translatedAction;
    sentence += ` Details: ${detail}`;
  } else if (!hasEndpoints && event.eventType && !/^unknown$/i.test(event.eventType)) {
    // Nothing else to show - at least name the event type so the sentence
    // isn't just "Vendor allowed."
    sentence = sentence.replace(/\.$/, ` (${event.eventType}).`);
  }

  return sentence;
}

module.exports = { buildReadableSummary, translateCommonTerms };
