import { v4 as uuidv4 } from 'uuid';
import { detectAndParse } from '../parsers/detect';
import { NormalizedEvent } from '../types';

// Takes a raw log string + the source type the user picked, and returns a
// fully normalized event object plus which format was detected. Throws if
// nothing could parse the log at all.
export function normalizeRawLog(rawLog: string, sourceType?: string): { normalized: NormalizedEvent; rawLog: string } {
  const detected = detectAndParse(rawLog);
  if (!detected) {
    const err: any = new Error('Could not detect or parse this log format.');
    err.status = 422;
    throw err;
  }

  const { formatName, fields } = detected;

  const normalized: NormalizedEvent = {
    eventId: uuidv4(),
    timestamp: fields.timestamp || new Date().toISOString(),
    sourceIP: fields.sourceIP || null,
    destIP: fields.destIP || null,
    action: fields.action || null,
    protocol: fields.protocol || null,
    vendor: fields.vendor || 'unknown',
    eventType: fields.eventType || 'unknown',
    sourceType: sourceType || formatName,
    detectedFormat: formatName,
  };

  return { normalized, rawLog };
}
