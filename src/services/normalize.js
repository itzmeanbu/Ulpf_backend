const { v4: uuidv4 } = require('uuid');
const { detectAndParse } = require('../parsers/detect');

// Takes a raw log string + the source type the user picked, and returns a
// fully normalized event object plus which format was detected. Throws if
// nothing could parse the log at all.
function normalizeRawLog(rawLog, sourceType) {
  const detected = detectAndParse(rawLog);
  if (!detected) {
    const err = new Error('Could not detect or parse this log format.');
    err.status = 422;
    throw err;
  }

  const { formatName, fields } = detected;

  const normalized = {
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

module.exports = { normalizeRawLog };
