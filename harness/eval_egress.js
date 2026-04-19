// End-to-end egress pipeline eval.
//
// Simulates the exact bytes that reach the Groq LLM API by chaining:
//   1. Client-side redact.js
//   2. Server-side sanitize() - prompt-injection stripper
//   3. Server-side scrubNames() - compromise NLP person-NER fallback
//
// Then measures what would actually be sent in the /api/parse request body.
// Each corpus doc is pushed through the full chain. Leak detection is
// canary-substring based (ZQK<id> is globally unique per doc).
//
// Output: ../results/egress_eval.json + CSVs

import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { createRequire } from 'module';
import { redact } from '../src/redact.js';

const require = createRequire(import.meta.url);
const { sanitize }   = require('../src/sanitize.js');
const { scrubNames } = require('../src/scrub.js');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.resolve(__dirname, '../corpus');
const RESULTS = path.resolve(__dirname, '../results');
fs.mkdirSync(RESULTS, { recursive: true });

const manifest = JSON.parse(fs.readFileSync(path.join(CORPUS, 'manifest.json'), 'utf8'));

// Emulate the exact /api/parse body the client sends to the proxy + what the
// server forwards to Groq.
function clientSends(rawText) {
  const { redacted } = redact(rawText);
  return { text: redacted };
}
function proxyForwardsToGroq(clientBody) {
  // Mirrors routes/parse.js logic:  scrubNames(sanitize(text))
  const scrubbed = scrubNames(sanitize(clientBody.text));
  return scrubbed;  // This string is what goes to the LLM in messages[1].content
}

const stages = [
  { name: 'raw_input',             fn: (doc, txt) => txt },
  { name: 'after_client_redaction', fn: (doc, txt) => clientSends(txt).text },
  { name: 'after_server_sanitize',  fn: (doc, txt) => sanitize(clientSends(txt).text) },
  { name: 'sent_to_groq',           fn: (doc, txt) => proxyForwardsToGroq(clientSends(txt)) },
];

const stageResults = {};
for (const s of stages) stageResults[s.name] = { canary_leaks: 0, phi_literal_leaks: 0, docs_any_leak: 0 };

const perDoc = [];
const groqLeaks = [];  // leaks that survive all the way to what is sent to Groq

for (const doc of manifest.docs) {
  const raw = fs.readFileSync(path.join(CORPUS, 'docs', doc.lang, `${doc.doc_id}.txt`), 'utf8');
  const truth = JSON.parse(fs.readFileSync(path.join(CORPUS, 'truth', doc.lang, `${doc.doc_id}.json`), 'utf8'));

  const docRow = { doc_id: doc.doc_id, lang: doc.lang, canary: truth.canary_token, stages: {} };

  for (const s of stages) {
    const t0 = process.hrtime.bigint();
    const out = s.fn(doc, raw);
    const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;

    const canaryLeaked = out.includes(truth.canary_token);
    let literalLeaks = 0;
    const leakedClasses = [];
    for (const f of truth.phi) {
      const useWB = f.class === 'age' || (f.class === 'account' && /^\d+$/.test(f.literal));
      const escaped = f.literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const hit = useWB ? new RegExp(`\\b${escaped}\\b`).test(out) : out.includes(f.literal);
      if (hit) { literalLeaks++; leakedClasses.push(f.class); }
    }

    stageResults[s.name].canary_leaks += canaryLeaked ? 1 : 0;
    stageResults[s.name].phi_literal_leaks += literalLeaks;
    if (canaryLeaked || literalLeaks > 0) stageResults[s.name].docs_any_leak++;

    docRow.stages[s.name] = { canary_leaked: canaryLeaked, literal_leaks: literalLeaks, leaked_classes: leakedClasses, ms: elapsedMs };

    if (s.name === 'sent_to_groq' && (canaryLeaked || literalLeaks > 0)) {
      groqLeaks.push({ doc_id: doc.doc_id, lang: doc.lang, canary: truth.canary_token,
                       leaked_classes: leakedClasses, canary_leaked: canaryLeaked,
                       output_preview: out.slice(0, 400) });
    }
  }
  perDoc.push(docRow);
}

const N = manifest.docs.length;

const summary = {
  generated_at: new Date().toISOString(),
  corpus: { total_docs: N, total_phi: N * 10 },
  pipeline: ['raw_input', 'after_client_redaction', 'after_server_sanitize', 'sent_to_groq'],
  stages: {},
  groq_input_leak_count: stageResults.sent_to_groq.canary_leaks,
  groq_input_phi_leak_count: stageResults.sent_to_groq.phi_literal_leaks,
  groq_input_docs_any_leak: stageResults.sent_to_groq.docs_any_leak,
  headline_claim: stageResults.sent_to_groq.canary_leaks === 0 && stageResults.sent_to_groq.phi_literal_leaks === 0
    ? `No PHI reached the LLM across all ${N} synthetic discharge documents.`
    : `PHI LEAK: ${stageResults.sent_to_groq.docs_any_leak}/${N} documents sent PHI to the LLM.`,
};
for (const s of stages) {
  const r = stageResults[s.name];
  summary.stages[s.name] = {
    canary_leaks: r.canary_leaks,
    canary_leak_rate: r.canary_leaks / N,
    phi_literal_leaks: r.phi_literal_leaks,
    phi_literal_leak_rate: r.phi_literal_leaks / (N * 10),
    docs_any_leak: r.docs_any_leak,
    docs_any_leak_rate: r.docs_any_leak / N,
  };
}

fs.writeFileSync(path.join(RESULTS, 'egress_eval.json'),
                 JSON.stringify({ summary, per_doc: perDoc, groq_leaks: groqLeaks }, null, 2));

// CSV — pipeline stage summary
const csv = ['stage,canary_leaks,canary_leak_rate,phi_literal_leaks,phi_literal_leak_rate,docs_any_leak'];
for (const s of stages) {
  const r = summary.stages[s.name];
  csv.push(`${s.name},${r.canary_leaks},${r.canary_leak_rate.toFixed(4)},${r.phi_literal_leaks},${r.phi_literal_leak_rate.toFixed(4)},${r.docs_any_leak}`);
}
fs.writeFileSync(path.join(RESULTS, 'egress_pipeline_stages.csv'), csv.join('\n'));

console.log(`\n=== Egress pipeline eval (N = ${N} docs, ${N*10} PHI instances) ===\n`);
console.log('stage                       | canary leaks | PHI lit leaks | docs w/ any leak');
console.log('----------------------------|--------------|---------------|-----------------');
for (const s of stages) {
  const r = summary.stages[s.name];
  console.log(`${s.name.padEnd(28)}|     ${String(r.canary_leaks).padStart(4)}     |    ${String(r.phi_literal_leaks).padStart(5)}      |       ${String(r.docs_any_leak).padStart(4)}`);
}
console.log(`\n${summary.headline_claim}`);
