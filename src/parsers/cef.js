// CEF format:
// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

function looksLikeCef(line) {
  return line.trim().startsWith('CEF:');
}

function parseCef(line) {
  const body = line.trim().slice(4); // strip "CEF:"
  const parts = body.split('|');
  if (parts.length < 7) return null;

  const [, vendor, product, , , name] = parts;
  const extension = parts.slice(7).join('|');
  const ext = parseExtension(extension);

  return {
    vendor: vendor || 'unknown-cef',
    eventType: name || product || 'cef-event',
    timestamp: ext.rt || new Date().toISOString(),
    sourceIP: ext.src || null,
    destIP: ext.dst || null,
    action: ext.act || name || null,
    protocol: ext.proto || null,
  };
}

// CEF extension is space-separated key=value pairs.
function parseExtension(ext) {
  const out = {};
  const re = /(\w+)=([^=]*?)(?=\s+\w+=|$)/g;
  let m;
  while ((m = re.exec(ext)) !== null) {
    out[m[1]] = m[2].trim();
  }
  return out;
}

module.exports = { looksLikeCef, parseCef };
