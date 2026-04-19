// Runs redact.js (the production on-device redactor) against every corpus
// document and computes per-class recall (PHI removed correctly) and
// specificity of keeping provider info (false-positive over-redaction).
//
// Results written to ../results/redaction_eval.json + .csv

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { redact } from '../src/redact.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.resolve(__dirname, '../corpus');
const RESULTS = path.resolve(__dirname, '../results');
fs.mkdirSync(RESULTS, { recursive: true });

const manifest = JSON.parse(fs.readFileSync(path.join(CORPUS, 'manifest.json'), 'utf8'));

// Per-PHI-class counters
const classStats = {};  // class -> { tp, fn, byLang: {lang: {tp, fn}} }
const providerStats = { hospital: 0, hospital_kept: 0,
                        doctor: 0, doctor_kept: 0,
                        medication: 0, medication_kept: 0,
                        diagnosis: 0, diagnosis_kept: 0,
                        appointment: 0, appointment_kept: 0,
                        hospital_phone: 0, hospital_phone_kept: 0 };

const perDoc = [];
const failures = [];  // PHI that was NOT redacted
let docCanaryLeaks = 0;

function ensureClass(c) {
  if (!classStats[c]) classStats[c] = { tp: 0, fn: 0, byLang: {} };
  return classStats[c];
}
function ensureLang(stat, lang) {
  if (!stat.byLang[lang]) stat.byLang[lang] = { tp: 0, fn: 0 };
  return stat.byLang[lang];
}

function containsLiteral(haystack, literal, opts = {}) {
  // For short purely-numeric literals (e.g., age "70"), use word-boundary
  // matching to avoid false-positive hits inside longer numbers (e.g., "77000").
  if (opts.wordBoundary) {
    const escaped = literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`\\b${escaped}\\b`).test(haystack);
  }
  return haystack.includes(literal);
}

for (const doc of manifest.docs) {
  const text = fs.readFileSync(path.join(CORPUS, 'docs', doc.lang, `${doc.doc_id}.txt`), 'utf8');
  const truth = JSON.parse(fs.readFileSync(path.join(CORPUS, 'truth', doc.lang, `${doc.doc_id}.json`), 'utf8'));

  const t0 = process.hrtime.bigint();
  const { redacted, piiFound } = redact(text);
  const tNs = process.hrtime.bigint() - t0;

  let docTp = 0, docFn = 0;
  const docFails = [];

  // Per-class recall = LITERAL still present in output.
  // Canary leakage is tracked separately at doc level since the canary is
  // doc-wide and a single source field's leak propagates via shared canary.
  for (const field of truth.phi) {
    const cs = ensureClass(field.class);
    const langStat = ensureLang(cs, doc.lang);

    // age and account fields can be short numerics — use word boundaries so
    // short digit sequences aren't false-matched inside longer numbers.
    const useWB = field.class === 'age' || (field.class === 'account' && /^\d+$/.test(field.literal));
    const leaked = containsLiteral(redacted, field.literal, { wordBoundary: useWB });

    if (leaked) {
      cs.fn++; langStat.fn++; docFn++;
      docFails.push({ class: field.class, literal: field.literal });
      failures.push({
        doc_id: doc.doc_id, lang: doc.lang, class: field.class,
        literal: field.literal, canary: field.canary,
      });
    } else {
      cs.tp++; langStat.tp++; docTp++;
    }
  }
  // Track any canary residue at doc level
  const canaryStillPresent = containsLiteral(redacted, truth.canary_token);
  if (canaryStillPresent) docCanaryLeaks++;

  // Provider-info keep rate (specificity)
  const p = truth.provider;
  providerStats.hospital++;
  if (redacted.includes(p.hospital)) providerStats.hospital_kept++;

  providerStats.doctor++;
  if (redacted.includes(p.doctor)) providerStats.doctor_kept++;

  providerStats.medication++;
  if (redacted.includes(p.medication)) providerStats.medication_kept++;

  providerStats.diagnosis++;
  if (redacted.includes(p.diagnosis)) providerStats.diagnosis_kept++;

  providerStats.appointment++;
  if (redacted.includes(p.appointment_date)) providerStats.appointment_kept++;

  providerStats.hospital_phone++;
  if (redacted.includes(p.hospital_phone)) providerStats.hospital_phone_kept++;

  perDoc.push({
    doc_id: doc.doc_id, lang: doc.lang,
    phi_total: truth.phi.length, phi_redacted: docTp, phi_leaked: docFn,
    ms: Number(tNs) / 1e6,
    pii_categories_reported: piiFound,
  });
}

// Aggregate summaries
const summary = {
  generated_at: new Date().toISOString(),
  corpus: { total_docs: manifest.docs.length, total_phi: manifest.docs.length * 10, languages: Object.keys(manifest.totals) },
  phi_recall_by_class: {},
  phi_recall_overall: {},
  phi_recall_by_lang: {},
  provider_info_keep_rate: {},
};

let totalTp = 0, totalFn = 0;
for (const [cls, s] of Object.entries(classStats)) {
  const n = s.tp + s.fn;
  summary.phi_recall_by_class[cls] = {
    n, removed: s.tp, leaked: s.fn, recall: n ? s.tp / n : null,
  };
  totalTp += s.tp; totalFn += s.fn;
  // Per-language breakdown for this class
  for (const [lang, ls] of Object.entries(s.byLang)) {
    if (!summary.phi_recall_by_lang[lang]) summary.phi_recall_by_lang[lang] = { tp: 0, fn: 0 };
    summary.phi_recall_by_lang[lang].tp += ls.tp;
    summary.phi_recall_by_lang[lang].fn += ls.fn;
  }
}
summary.phi_recall_overall = {
  n: totalTp + totalFn, removed: totalTp, leaked: totalFn,
  recall: (totalTp + totalFn) ? totalTp / (totalTp + totalFn) : null,
};
for (const [lang, s] of Object.entries(summary.phi_recall_by_lang)) {
  s.recall = (s.tp + s.fn) ? s.tp / (s.tp + s.fn) : null;
}
summary.provider_info_keep_rate = {
  hospital_name: providerStats.hospital_kept / providerStats.hospital,
  doctor_name: providerStats.doctor_kept / providerStats.doctor,
  medication: providerStats.medication_kept / providerStats.medication,
  diagnosis: providerStats.diagnosis_kept / providerStats.diagnosis,
  appointment_date: providerStats.appointment_kept / providerStats.appointment,
  hospital_phone: providerStats.hospital_phone_kept / providerStats.hospital_phone,
};

// Per-doc latency distribution
const mss = perDoc.map(d => d.ms).sort((a, b) => a - b);
summary.latency_ms = {
  n: mss.length,
  min: mss[0], median: mss[Math.floor(mss.length / 2)],
  p95: mss[Math.floor(mss.length * 0.95)], max: mss[mss.length - 1],
  mean: mss.reduce((a, b) => a + b, 0) / mss.length,
};

fs.writeFileSync(path.join(RESULTS, 'redaction_eval.json'),
                 JSON.stringify({ summary, per_doc: perDoc, failures }, null, 2));

// CSV of per-class recall
const csvLines = ['class,n,removed,leaked,recall'];
for (const [cls, s] of Object.entries(summary.phi_recall_by_class)) {
  csvLines.push(`${cls},${s.n},${s.removed},${s.leaked},${s.recall.toFixed(4)}`);
}
fs.writeFileSync(path.join(RESULTS, 'redaction_recall_by_class.csv'), csvLines.join('\n'));

// CSV of per-language overall recall
const langLines = ['language,tp,fn,recall'];
for (const [lang, s] of Object.entries(summary.phi_recall_by_lang)) {
  langLines.push(`${lang},${s.tp},${s.fn},${s.recall.toFixed(4)}`);
}
fs.writeFileSync(path.join(RESULTS, 'redaction_recall_by_lang.csv'), langLines.join('\n'));

console.log(`\n=== PHI redaction recall ===`);
console.log(`Overall: ${summary.phi_recall_overall.removed}/${summary.phi_recall_overall.n} = ${(summary.phi_recall_overall.recall * 100).toFixed(2)}%`);
console.log(`\nBy class:`);
for (const [cls, s] of Object.entries(summary.phi_recall_by_class)) {
  console.log(`  ${cls.padEnd(12)} ${s.removed}/${s.n} = ${(s.recall * 100).toFixed(2)}%`);
}
console.log(`\nBy language:`);
for (const [lang, s] of Object.entries(summary.phi_recall_by_lang)) {
  console.log(`  ${lang.padEnd(4)} ${s.tp}/${s.tp + s.fn} = ${(s.recall * 100).toFixed(2)}%`);
}
console.log(`\n=== Provider info kept (specificity) ===`);
for (const [k, v] of Object.entries(summary.provider_info_keep_rate)) {
  console.log(`  ${k.padEnd(20)} ${(v * 100).toFixed(1)}%`);
}
console.log(`\n=== Redaction latency per document (ms) ===`);
console.log(`  median ${summary.latency_ms.median.toFixed(2)}  p95 ${summary.latency_ms.p95.toFixed(2)}  max ${summary.latency_ms.max.toFixed(2)}`);
console.log(`\nDoc-level canary residue: ${docCanaryLeaks}/${manifest.docs.length} docs had at least one canary token remaining`);
console.log(`Total PHI literal failures: ${failures.length}  (see results/redaction_eval.json → failures[])`);

summary.doc_canary_leaks = docCanaryLeaks;
summary.doc_canary_leak_rate = docCanaryLeaks / manifest.docs.length;
fs.writeFileSync(path.join(RESULTS, 'redaction_eval.json'),
                 JSON.stringify({ summary, per_doc: perDoc, failures }, null, 2));
