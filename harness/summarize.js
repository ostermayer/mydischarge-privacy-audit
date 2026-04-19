// Aggregates redaction_eval.json + egress_eval.json into a single summary.json
// that the paper drafts and figures can read directly.

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.resolve(__dirname, '../results');

const red = JSON.parse(fs.readFileSync(path.join(RESULTS, 'redaction_eval.json'), 'utf8'));
const egr = JSON.parse(fs.readFileSync(path.join(RESULTS, 'egress_eval.json'), 'utf8'));

const summary = {
  generated_at: new Date().toISOString(),
  corpus: red.summary.corpus,
  redaction: {
    overall_recall: red.summary.phi_recall_overall.recall,
    overall_n: red.summary.phi_recall_overall.n,
    overall_removed: red.summary.phi_recall_overall.removed,
    overall_leaked: red.summary.phi_recall_overall.leaked,
    by_class: red.summary.phi_recall_by_class,
    by_language: red.summary.phi_recall_by_lang,
    provider_keep_rate: red.summary.provider_info_keep_rate,
    doc_canary_leaks: red.summary.doc_canary_leaks,
    latency_ms: red.summary.latency_ms,
  },
  egress_pipeline: {
    stages: egr.summary.stages,
    headline: egr.summary.headline_claim,
    groq_input_leaks: egr.summary.groq_input_leak_count,
    groq_input_phi_literal_leaks: egr.summary.groq_input_phi_leak_count,
    groq_input_docs_any_leak: egr.summary.groq_input_docs_any_leak,
  },
};

fs.writeFileSync(path.join(RESULTS, 'summary.json'), JSON.stringify(summary, null, 2));

console.log('=== MyDischarge Privacy Validation — Summary ===\n');
console.log(`Corpus:               ${summary.corpus.total_docs} docs, ${summary.corpus.total_phi} PHI instances, ${summary.corpus.languages.length} languages`);
console.log(`Redaction recall:     ${(summary.redaction.overall_recall*100).toFixed(2)}%   (${summary.redaction.overall_removed}/${summary.redaction.overall_n})`);
console.log(`Doc-level canary leaks: ${summary.redaction.doc_canary_leaks}/${summary.corpus.total_docs}`);
console.log(`Redaction latency:    median ${summary.redaction.latency_ms.median.toFixed(2)} ms  p95 ${summary.redaction.latency_ms.p95.toFixed(2)} ms\n`);
console.log('PHI reaching LLM (end-to-end pipeline):');
for (const [stage, s] of Object.entries(summary.egress_pipeline.stages)) {
  console.log(`  ${stage.padEnd(26)}  canary_leaks=${String(s.canary_leaks).padStart(4)}  literal_leaks=${String(s.phi_literal_leaks).padStart(4)}`);
}
console.log(`\n${summary.egress_pipeline.headline}`);
