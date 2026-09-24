// Turns a normalized (or masked) log event into ONE plain-English sentence,
// e.g. "Cisco ASA blocked a TCP connection from 192.168.xxx.xxx to
// 10.0.xxx.xxx." This is what powers the "readable" part of ULPF.

const TERM_MAP: [RegExp, string][] = [
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

export function translateCommonTerms(text: string | null | undefined): any {
  if (!text || typeof text !== 'string') return text;
  let out = text;
  for (const [pattern, replacement] of TERM_MAP) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

function classifyVerb(actionText: string | null | undefined, eventType: string | null | undefined): string {
  const t = `${actionText || ''} ${eventType || ''}`.toLowerCase();
  if (/deny|denied|block|blocked|drop|reject|refus/.test(t)) return 'blocked';
  if (/fail|invalid|unauthori[sz]ed|incorrect|auth-failure/.test(t)) return 'flagged a failed attempt on';
  if (/error|critical|fatal|exception/.test(t)) return 'hit an error during';
  if (/warn/.test(t)) return 'raised a warning during';
  if (/allow|accept|permit|success|logged in|login/.test(t)) return 'allowed';
  return 'logged';
}

export function buildReadableSummary(event: any): string {
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

  const wordCount = translatedAction ? translatedAction.trim().split(/\s+/).length : 0;
  if (wordCount > 2) {
    const detail = translatedAction.length > 200 ? `${translatedAction.slice(0, 200)}...` : translatedAction;
    sentence += ` Details: ${detail}`;
  } else if (!hasEndpoints && event.eventType && !/^unknown$/i.test(event.eventType)) {
    sentence = sentence.replace(/\.$/, ` (${event.eventType}).`);
  }

  return sentence;
}
