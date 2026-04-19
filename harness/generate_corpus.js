// Generates the synthetic canary corpus.
//
// Output: ../corpus/docs/<lang>/<serial>.txt and ../corpus/truth/<lang>/<serial>.json
// Each doc has a document-unique canary token (ZQKxxxx) embedded in every PHI value
// so later grep-based leak detection is deterministic and false-positive-free.

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import seedrandom from 'seedrandom';
import { LANGUAGES, TEMPLATES } from './templates.js';
import { buildPhiSet, buildProviderInfo, CANARY_PREFIX } from './phi_pool.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CORPUS_ROOT = path.resolve(__dirname, '../corpus');
const DOCS_ROOT = path.join(CORPUS_ROOT, 'docs');
const TRUTH_ROOT = path.join(CORPUS_ROOT, 'truth');

// Docs per language. EN and ES are primary (pilot languages); others get fewer.
const DOCS_PER_LANG = {
  EN: 60, ES: 60,
  ZH: 30, VI: 30, FR: 30, AR: 30, PT: 30, DE: 30,
  KO: 20, TL: 20, RU: 20, HT: 20, JA: 20, HI: 20, FA: 20,
};

function substitute(template, phiMap, provider) {
  let out = template;
  for (const [k, v] of Object.entries(phiMap)) {
    out = out.replaceAll(`%${k}%`, v);
  }
  for (const [k, v] of Object.entries(provider)) {
    out = out.replaceAll(`%${k}%`, v);
  }
  return out;
}

function main() {
  fs.mkdirSync(DOCS_ROOT, { recursive: true });
  fs.mkdirSync(TRUTH_ROOT, { recursive: true });

  let serial = 1;
  const manifest = { docs: [], totals: {}, created: new Date().toISOString() };

  for (const lang of LANGUAGES) {
    const templates = TEMPLATES[lang];
    if (!templates) { console.warn(`No templates for ${lang}, skipping`); continue; }
    const n = DOCS_PER_LANG[lang] ?? 20;

    fs.mkdirSync(path.join(DOCS_ROOT, lang), { recursive: true });
    fs.mkdirSync(path.join(TRUTH_ROOT, lang), { recursive: true });

    for (let i = 0; i < n; i++) {
      const rng = seedrandom(`mydischarge-canary-${lang}-${i}`);
      const phiSet = buildPhiSet(serial, rng);
      const provider = buildProviderInfo(serial, rng);
      const template = templates[i % templates.length];

      const phiMap = {
        NAME: phiSet.fields.find(f => f.class === 'name').literal,
        DOB: phiSet.fields.find(f => f.class === 'dob').literal,
        AGE: phiSet.fields.find(f => f.class === 'age').literal,
        SSN: phiSet.fields.find(f => f.class === 'ssn').literal,
        PHONE: phiSet.fields.find(f => f.class === 'phone').literal,
        EMAIL: phiSet.fields.find(f => f.class === 'email').literal,
        MRN: phiSet.fields.find(f => f.class === 'mrn').literal,
        INS: phiSet.fields.find(f => f.class === 'insurance').literal,
        ACCT: phiSet.fields.find(f => f.class === 'account').literal,
        ADDR: phiSet.fields.find(f => f.class === 'address').literal,
      };
      const providerMap = {
        HOSP: provider.hospital,
        HOSPPHONE: provider.hospitalPhone,
        DOC: provider.doctor,
        DRUG: provider.medication,
        DX: provider.diagnosis,
        APPT: provider.appointmentDate,
      };

      const text = substitute(template, phiMap, providerMap);
      const docId = String(serial).padStart(5, '0');

      const truth = {
        doc_id: docId,
        language: lang,
        template_index: i % templates.length,
        canary_token: phiSet.canaryToken,
        phi: phiSet.fields.map(f => ({
          class: f.class,
          literal: f.literal,
          canary: f.canary,
          required: f.required,
        })),
        provider: {
          hospital: provider.hospital,
          hospital_phone: provider.hospitalPhone,
          doctor: provider.doctor,
          medication: provider.medication,
          diagnosis: provider.diagnosis,
          appointment_date: provider.appointmentDate,
        },
      };

      fs.writeFileSync(path.join(DOCS_ROOT, lang, `${docId}.txt`), text);
      fs.writeFileSync(path.join(TRUTH_ROOT, lang, `${docId}.json`), JSON.stringify(truth, null, 2));

      manifest.docs.push({ doc_id: docId, lang, template_index: i % templates.length, canary: phiSet.canaryToken });
      serial++;
    }
    manifest.totals[lang] = n;
  }

  fs.writeFileSync(path.join(CORPUS_ROOT, 'manifest.json'), JSON.stringify(manifest, null, 2));

  const totalDocs = manifest.docs.length;
  const totalPhi  = totalDocs * 10;  // 10 PHI fields per doc
  console.log(`Generated ${totalDocs} synthetic discharge documents`);
  console.log(`Total PHI instances: ${totalPhi} (${Object.keys(DOCS_PER_LANG).length} languages)`);
  console.log(`Canary prefix: ${CANARY_PREFIX}  (doc-unique 7-char tokens)`);
  console.log(`Corpus root: ${CORPUS_ROOT}`);
}

main();
