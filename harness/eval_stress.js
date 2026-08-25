// Stress-corpus evaluation.
// Runs each stress document through the FULL production pipeline:
//   client redact.js  →  server sanitize.js  →  server scrubNames (compromise NER)
// and reports per-category PHI egress leakage.

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { redact } from '../src/redact.js';

const require = createRequire(import.meta.url);
const { sanitize }   = require('../src/sanitize.js');
const { scrubNames } = require('../src/scrub.js');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STRESS = path.resolve(__dirname, '../corpus/stress');
const RESULTS = path.resolve(__dirname, '../results');
fs.mkdirSync(RESULTS, { recursive: true });

const manifest = JSON.parse(fs.readFileSync(path.join(STRESS, 'manifest.json'), 'utf8'));

function pipelineStages(raw) {
  const { redacted } = redact(raw);
  const sanitized = sanitize(redacted);
  const scrubbed = scrubNames(sanitized);
  return { raw, client: redacted, server_sanitize: sanitized, groq_input: scrubbed };
}

function literalLeakCheck(text, literal, cls) {
  const useWB = cls === 'age' || (cls === 'account' && /^\d+$/.test(literal));
  if (useWB) {
    const esc = literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`\\b${esc}\\b`).test(text);
  }
  return text.includes(literal);
}

const categories = Object.keys(manifest.categories);
const results = {};
const perDoc = [];
const failureExamples = {};  // category -> first 3 failures

for (const category of categories) {
  const dir = path.join(STRESS, category);
  const docs = fs.readdirSync(dir).filter(f => f.endsWith('.txt'));
  results[category] = {
    n_docs: docs.length,
    n_phi: 0,
    stages: {
      client:          { canary_leaks: 0, literal_leaks: 0, docs_any_leak: 0 },
      server_sanitize: { canary_leaks: 0, literal_leaks: 0, docs_any_leak: 0 },
      groq_input:      { canary_leaks: 0, literal_leaks: 0, docs_any_leak: 0 },
    },
    leaks_by_class: {},
  };
  failureExamples[category] = [];

  for (const file of docs) {
    const docId = file.replace('.txt', '');
    const text = fs.readFileSync(path.join(dir, file), 'utf8');
    const truth = JSON.parse(fs.readFileSync(path.join(dir, `${docId}.truth.json`), 'utf8'));
    const stages = pipelineStages(text);

    results[category].n_phi += truth.phi.length;

    for (const stageName of ['client', 'server_sanitize', 'groq_input']) {
      const out = stages[stageName];
      const canaryLeaked = out.includes(truth.canary_token);
      let literalLeaks = 0;
      const leakedCls = [];
      for (const f of truth.phi) {
        if (literalLeakCheck(out, f.literal, f.class)) {
          literalLeaks++;
          leakedCls.push(f.class);
          if (stageName === 'groq_input') {
            results[category].leaks_by_class[f.class] = (results[category].leaks_by_class[f.class] || 0) + 1;
          }
        }
      }
      const stg = results[category].stages[stageName];
      stg.canary_leaks += canaryLeaked ? 1 : 0;
      stg.literal_leaks += literalLeaks;
      if (canaryLeaked || literalLeaks > 0) stg.docs_any_leak++;

      if (stageName === 'groq_input' && (canaryLeaked || literalLeaks > 0) && failureExamples[category].length < 3) {
        failureExamples[category].push({
          doc_id: docId, canary_leaked: canaryLeaked,
          leaked_classes: leakedCls, groq_preview: out.slice(0, 300),
        });
      }
    }

    perDoc.push({ category, doc_id: docId, canary: truth.canary_token });
  }
}

// Aggregate totals
const overall = { n_docs: 0, n_phi: 0,
  stages: { client: { canary_leaks: 0, literal_leaks: 0, docs_any_leak: 0 },
            server_sanitize: { canary_leaks: 0, literal_leaks: 0, docs_any_leak: 0 },
            groq_input: { canary_leaks: 0, literal_leaks: 0, docs_any_leak: 0 } } };
for (const c of categories) {
  overall.n_docs += results[c].n_docs;
  overall.n_phi  += results[c].n_phi;
  for (const stg of ['client', 'server_sanitize', 'groq_input']) {
    overall.stages[stg].canary_leaks  += results[c].stages[stg].canary_leaks;
    overall.stages[stg].literal_leaks += results[c].stages[stg].literal_leaks;
    overall.stages[stg].docs_any_leak += results[c].stages[stg].docs_any_leak;
  }
}

const summary = {
  generated_at: new Date().toISOString(),
  corpus: { total_docs: overall.n_docs, total_phi: overall.n_phi, categories: manifest.categories },
  by_category: results,
  overall,
  failure_examples: failureExamples,
};

fs.writeFileSync(path.join(RESULTS, 'stress_eval.json'), JSON.stringify(summary, null, 2));

// CSV per-category, per-stage
const rows = ['category,stage,canary_leaks,literal_leaks,docs_any_leak,n_docs,n_phi'];
for (const c of categories) {
  for (const stg of ['client', 'server_sanitize', 'groq_input']) {
    const s = results[c].stages[stg];
    rows.push(`${c},${stg},${s.canary_leaks},${s.literal_leaks},${s.docs_any_leak},${results[c].n_docs},${results[c].n_phi}`);
  }
}
fs.writeFileSync(path.join(RESULTS, 'stress_eval.csv'), rows.join('\n'));

// Console report
console.log(`\n=== Stress corpus eval (${overall.n_docs} docs, ${overall.n_phi} PHI instances) ===\n`);
console.log('category     | stage            | canary | literal | docs w/ leak | recall');
console.log('-------------|------------------|--------|---------|--------------|-------');
for (const c of categories) {
  for (const stg of ['client', 'groq_input']) {
    const s = results[c].stages[stg];
    const recall = ((results[c].n_phi - s.literal_leaks) / results[c].n_phi * 100).toFixed(1);
    console.log(`${c.padEnd(12)} | ${stg.padEnd(16)} | ${String(s.canary_leaks).padStart(6)} | ${String(s.literal_leaks).padStart(7)} | ${String(s.docs_any_leak).padStart(6)}/${String(results[c].n_docs).padEnd(4)} | ${recall}%`);
  }
}
console.log('\n=== Overall (groq_input stage) ===');
const o = overall.stages.groq_input;
console.log(`  canary_leaks: ${o.canary_leaks}/${overall.n_docs} docs`);
console.log(`  phi_literal_leaks: ${o.literal_leaks}/${overall.n_phi} instances`);
console.log(`  overall recall: ${((overall.n_phi - o.literal_leaks) / overall.n_phi * 100).toFixed(2)}%`);
console.log('\n=== Leaks by PHI class (groq_input) ===');
const byClass = {};
for (const c of categories) for (const [cls, n] of Object.entries(results[c].leaks_by_class)) {
  byClass[cls] = (byClass[cls] || 0) + n;
}
for (const [cls, n] of Object.entries(byClass).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${cls.padEnd(12)} ${n} leaks`);
}
