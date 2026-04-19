/**
 * Server-side NER scrubber — catches any person names that slipped
 * past the on-device regex redaction before text reaches Groq.
 *
 * Runs compromise NLP to detect person names, then replaces them
 * with [REDACTED]. Preserves names that appear near provider/doctor
 * context so follow-up doctor names are kept.
 */

const nlp = require('compromise');

// Word-boundary anchors on short Latin tokens ('pa', 'md', 'np', 'rn', 'dr')
// are required — without them, 'pa' matches 'patient', 'rn' matches 'return',
// etc., causing nearly every clinical line to be classified as provider
// context and suppressing the scrubber entirely.
const PROVIDER_CONTEXT = new RegExp([
  '\\battending\\b', '\\bphysician\\b', '\\bdoctor\\b', '\\bprovider\\b',
  '\\bdr\\.?\\b', '\\bmd\\b', '\\bnp\\b', '\\bpa\\b', '\\brn\\b',
  '\\bnurse\\b', '\\bhospital\\b', '\\bclinic\\b', '\\bfacility\\b',
  '\\bdepartment\\b', '\\breferred\\b', 'follow.?up with',
  '\\bm[eé]dico\\b', '\\bdoctora?\\b', '\\benfermer[oa]\\b',
  'bác sĩ', '医生', '医师', 'врач',
  '\\bdoktor\\b', '\\barzt\\b',
  'طبيب', 'دکتر', 'पزشک', 'چिकित्सक',
].join('|'), 'i');

const REDACTED = '[REDACTED]';

function scrubNames(text) {
  if (!text || text.length < 10) return text;

  const doc = nlp(text);
  const names = doc.people().out('array');

  if (names.length === 0) return text;

  const lines = text.split('\n');
  let result = text;

  for (const name of names) {
    // compromise often includes trailing punctuation (', ', '.', ',') in the
    // extracted token. Strip it so the word-boundary anchored replace below
    // can actually match the name in-place.
    const trimmed = name.trim().replace(/[.,;:!?'")\]]+$/u, '').replace(/^['("[]+/u, '');
    if (trimmed.length < 2 || trimmed === REDACTED) continue;

    // Check if this name appears on a line with provider/doctor context — keep it
    const isProviderName = lines.some((line) =>
      line.toLowerCase().includes(trimmed.toLowerCase()) && PROVIDER_CONTEXT.test(line)
    );

    if (!isProviderName) {
      const escaped = trimmed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      result = result.replace(new RegExp(`\\b${escaped}\\b`, 'gi'), REDACTED);
    }
  }

  return result;
}

module.exports = { scrubNames };
