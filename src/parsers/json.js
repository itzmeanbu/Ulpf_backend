function looksLikeJson(text) {
  const t = text.trim();
  return t.startsWith('{') || t.startsWith('[');
}

function parseJson(text) {
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    return null;
  }
  if (Array.isArray(obj)) obj = obj[0] || {};

  // Map some common vendor field name variants to the common schema.
  return {
    vendor: obj.vendor || obj.product || 'unknown-json',
    eventType: obj.eventType || obj.type || obj.event_type || 'unknown',
    timestamp: obj.timestamp || obj.time || obj['@timestamp'] || new Date().toISOString(),
    sourceIP: obj.sourceIP || obj.src_ip || obj.srcip || obj.source_ip || null,
    destIP: obj.destIP || obj.dst_ip || obj.dstip || obj.destination_ip || null,
    action: obj.action || obj.message || obj.msg || null,
    protocol: obj.protocol || obj.proto || null,
  };
}

module.exports = { looksLikeJson, parseJson };
