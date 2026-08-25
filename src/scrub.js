/**
 * Server-side NER scrubber — catches any person names that slipped
 * past the on-device regex redaction before text reaches Groq.
 *
 * Runs compromise NLP to detect person names, then replaces them
 * with [REDACTED]. Preserves names that appear near provider/doctor
 * context so follow-up doctor names are kept.
 */

const nlp = require('compromise');

const REDACTED = '[REDACTED]';

// A name is only kept when provider context is ADJACENT to it, not merely
// somewhere on the same line — OCR merges two-column headers into single
// lines, so "Memorial Hermann Hospital — John Smith" must not whitelist the
// patient name. Three keep conditions:
//   (a) a provider title immediately before the name ("Dr. John Smith",
//       "follow up with John Smith"),
//   (b) an institution word immediately after ("Memorial Hermann Hospital"),
//   (c) a credential immediately after ("John Smith, MD").
const PROVIDER_TITLE_BEFORE = /(?:dr\.?|doctor|physician|nurse|np|pa|rn|provider|attending|referred\s+to|follow\s*.?up\s+with|m[eé]dico|doctora?|enfermer[oa])\s*[:.]?\s*$/i;
const INSTITUTION_AFTER = /^\s+(?:Hospital|Medical|Health|Clinic|Center|Centre|Klinik|Cl[ií]nica)\b/i;
const CREDENTIAL_AFTER = /^\s*,?\s*(?:MD|DO|NP|PA|RN|APRN|DDS|PharmD)\b/;

function isProviderAdjacent(text, index, length) {
  const before = text.slice(Math.max(0, index - 40), index);
  const after = text.slice(index + length, index + length + 24);
  if (PROVIDER_TITLE_BEFORE.test(before)) return true;
  if (INSTITUTION_AFTER.test(after)) return true;
  if (CREDENTIAL_AFTER.test(after)) return true;
  return false;
}

function scrubNames(text) {
  if (!text || text.length < 10) return text;

  const doc = nlp(text);
  const names = doc.people().out('array');

  if (names.length === 0) return text;

  let result = text;

  for (const name of names) {
    // compromise often includes trailing punctuation (', ', '.', ',') in the
    // extracted token. Strip it so the word-boundary anchored replace below
    // can actually match the name in-place.
    const trimmed = name.trim()
      .replace(/[.,;:!?'")\]]+$/u, '')
      .replace(/^['("[]+/u, '')
      // compromise sometimes folds a preceding institution word and dash into
      // the person token ("Hospital — John Smith") — strip it so only the
      // actual name is replaced.
      .replace(/^(?:(?:Hospital|Medical|Health|Clinic|Center|Centre|Klinik|Cl[ií]nica)\b[\s—–-]*)+/i, '')
      .replace(/^[\s—–-]+/u, '');
    if (trimmed.length < 2 || trimmed === REDACTED) continue;

    const escaped = trimmed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // \b is ASCII-only and never matches at an accented edge, so "José" or
    // "Álvarez" would slip this barrier entirely. Latin-aware lookarounds
    // stand in for the word boundary.
    const B = 'A-Za-zÀ-ÖØ-öø-ÿĀ-ſḀ-ỿ0-9_';
    result = result.replace(
      new RegExp(`(?<![${B}])${escaped}(?![${B}])`, 'giu'),
      (m, offset, str) => (isProviderAdjacent(str, offset, m.length) ? m : REDACTED),
    );
  }

  return result;
}

module.exports = { scrubNames };
