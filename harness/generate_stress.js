// Stress corpus generator.
//
// Builds adversarial discharge documents that resemble the messiness of real
// AVS paperwork: OCR errors, narrative PHI without labels, typos in labels,
// multi-line formatting, duplicated identifiers, and unlabeled PHI.
//
// Each stress doc still carries a document-unique canary (ZQK####) embedded
// in every PHI value so leakage is grep-detectable.
//
// Output: ../corpus/stress/<category>/<id>.txt  and matching truth JSON.

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import seedrandom from 'seedrandom';
import { canaryToken } from './phi_pool.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STRESS_ROOT = path.resolve(__dirname, '../corpus/stress');
fs.mkdirSync(STRESS_ROOT, { recursive: true });

// Start stress serials above the basic-corpus range (which ended at 440)
// so canary tokens don't collide.
let serial = 1001;

function nextCanary() { return canaryToken(serial++); }

function phiSet(tok) {
  return {
    name:      `Marcus Thornton-${tok}`,
    dob:       '03/14/1962',
    age:       '63',
    ssn:       `900-44-${tok.slice(-4)}`,
    phone:     `555-020-${tok.slice(-4)}`,
    email:     `canary-${tok.toLowerCase()}@example.invalid`,
    mrn:       `MRN${tok}`,
    insurance: `INS${tok}XYZ`,
    account:   `9${tok.replace(/[^0-9]/g, '').padStart(7, '0')}`,
    address:   `14 Canary-${tok} Ct, Testville, TX 77000`,
  };
}

// Writes one stress doc + its ground-truth JSON.
// Only classes actually present in the text are listed in truth; an absent
// class must not be counted as "correctly redacted".
function writeDoc(category, localId, text, phi, presentClasses) {
  const dir = path.join(STRESS_ROOT, category);
  fs.mkdirSync(dir, { recursive: true });
  const docId = `${category}-${String(localId).padStart(3, '0')}`;
  const truth = {
    doc_id: docId,
    category,
    canary_token: phi.__canary,
    phi: presentClasses.map(cls => ({
      class: cls, literal: phi[cls], canary: phi.__canary, required: true,
    })),
  };
  fs.writeFileSync(path.join(dir, `${docId}.txt`), text);
  fs.writeFileSync(path.join(dir, `${docId}.truth.json`), JSON.stringify(truth, null, 2));
  return docId;
}

const ALL_CLASSES = ['name','dob','age','ssn','phone','email','mrn','insurance','account','address'];

// ─────────────────────────────────────────────────────────────
// Category A — OCR errors
// Simulates the label-corruption typical of mobile-phone OCR of printed paper.
// Character confusions: O↔0, l↔1, rn→m, cl→d; dropped spaces; bad colons.
// ─────────────────────────────────────────────────────────────
function ocrCorrupt(s, rng) {
  const subs = [[/O/g,'0'], [/l/g,'1'], [/rn/g,'m'], [/cl/g,'d'], [/: /g,':'], [/  /g,' ']];
  let out = s;
  for (const [from, to] of subs) {
    if (rng() < 0.25) out = out.replace(from, to);
  }
  // 10% chance to drop a random colon
  if (rng() < 0.10) out = out.replace(/:/, ' ');
  return out;
}

function buildOcr(n) {
  const ids = [];
  for (let i = 0; i < n; i++) {
    const rng = seedrandom(`stress-ocr-${i}`);
    const tok = nextCanary();
    const p = phiSet(tok);
    const clean =
`DISCHARGE INSTRUCTIONS
Facility: Memorial Hermann TMC
Hospital Phone: 713-500-7878

Patient Name: ${p.name}
DOB: ${p.dob}   Age: ${p.age}
SSN: ${p.ssn}
Patient Phone: ${p.phone}
Patient Email: ${p.email}
Patient Address: ${p.address}
MRN: ${p.mrn}
Insurance ID: ${p.insurance}
Account: ${p.account}

Follow up in 1 week.`;
    const dirty = ocrCorrupt(clean, rng);
    ids.push(writeDoc('ocr', i, dirty, { ...p, __canary: tok }, ALL_CLASSES));
  }
  return ids;
}

// ─────────────────────────────────────────────────────────────
// Category B — Narrative PHI (no explicit labels in many places)
// PHI embedded in free-text sentences. Tests name propagation + NER fallback.
// ─────────────────────────────────────────────────────────────
function buildNarrative(n) {
  const ids = [];
  for (let i = 0; i < n; i++) {
    const tok = nextCanary();
    const p = phiSet(tok);
    const text =
`EMERGENCY DEPARTMENT NOTE
Patient ${p.name} presented today complaining of sore throat.
Date of birth ${p.dob}; the patient is ${p.age} years old.
His record number is ${p.mrn} and his insurance plan ID is ${p.insurance}.
Reachable at ${p.phone} or ${p.email}.
Lives at ${p.address}.
${p.name} was discharged home in stable condition.
Social security on file ends in ${p.ssn.slice(-4)} (full: ${p.ssn}). Account ${p.account}.
If ${p.name.split(' ')[0]} has any questions, please call our clinic at 713-500-7878.`;
    ids.push(writeDoc('narrative', i, text, { ...p, __canary: tok },
      ['name','dob','age','ssn','phone','email','mrn','insurance','account','address']));
  }
  return ids;
}

// ─────────────────────────────────────────────────────────────
// Category C — Label typos / physician shorthand
// "Patiient Name", "Pt Nme", "P/t:", etc.
// ─────────────────────────────────────────────────────────────
function buildTypos(n) {
  const typoSets = [
    { name: 'Patiient Name', dob: 'D.0.B', addr: 'Home Addres', phone: 'Pt Phone' },
    { name: 'Pt Nme', dob: 'DoB', addr: 'Patient Adress', phone: 'Patient Tel' },
    { name: 'Patient/Name', dob: 'Birth date', addr: 'Addr', phone: 'Cell#' },
    { name: 'PATIENT  NAME', dob: 'DATE  OF  BIRTH', addr: 'HOME ADDRESS', phone: 'CELL PHONE' },
  ];
  const ids = [];
  for (let i = 0; i < n; i++) {
    const tok = nextCanary();
    const p = phiSet(tok);
    const t = typoSets[i % typoSets.length];
    const text =
`DISCHARGE SUMMARY
${t.name}: ${p.name}
${t.dob}: ${p.dob}
${t.addr}: ${p.address}
${t.phone}: ${p.phone}
SSN: ${p.ssn}
MRN: ${p.mrn}
Insurance: ${p.insurance}
Acct: ${p.account}
Email: ${p.email}

Age: ${p.age} y
Attending: Dr. Lee
Dx: viral pharyngitis
Rx: supportive care`;
    ids.push(writeDoc('typos', i, text, { ...p, __canary: tok }, ALL_CLASSES));
  }
  return ids;
}

// ─────────────────────────────────────────────────────────────
// Category D — Multi-line / layout edge cases
// Address on 3 lines; label-newline-value; tables; columnar layouts.
// ─────────────────────────────────────────────────────────────
function buildMultiline(n) {
  const ids = [];
  for (let i = 0; i < n; i++) {
    const tok = nextCanary();
    const p = phiSet(tok);
    const parts = p.address.split(', ');
    const text =
`After Visit Summary

Patient Name:
${p.name}

Date of Birth:
${p.dob}

Home Address:
${parts[0]}
${parts.slice(1).join(', ')}

Contact:
Cell: ${p.phone}
Email: ${p.email}

Medical Record Number:    ${p.mrn}
Insurance Member ID:       ${p.insurance}
SSN:                       ${p.ssn}
Account #:                 ${p.account}

Age:
${p.age}

Attending physician: Dr. Carlos Ruiz
Diagnosis: urinary tract infection
Medication: nitrofurantoin 100 mg twice daily for 5 days.`;
    ids.push(writeDoc('multiline', i, text, { ...p, __canary: tok }, ALL_CLASSES));
  }
  return ids;
}

// ─────────────────────────────────────────────────────────────
// Category E — Duplicated PHI
// Same name appears 6+ times in header, body, footer, signature line.
// Tests whether name-propagation catches all occurrences.
// ─────────────────────────────────────────────────────────────
function buildDuplicated(n) {
  const ids = [];
  for (let i = 0; i < n; i++) {
    const tok = nextCanary();
    const p = phiSet(tok);
    const first = p.name.split(' ')[0];
    const text =
`Memorial Hermann TMC — Discharge Summary for ${p.name}

Patient Name: ${p.name}
DOB: ${p.dob}
MRN: ${p.mrn}

Dear ${first},

You were seen today in our emergency department. ${first}, you had symptoms of
chest pain. We performed an ECG and labs. ${p.name}, your results were normal.

${first}, please follow up with your primary care provider in 3 days.

If you, ${first}, develop any new symptoms, return to the ED.

Patient signature: ${p.name}   Date: 4/13/2026
Printed: ${p.name}
Copy to file under MRN ${p.mrn}.`;
    // This category only exercises name propagation — only these classes are present.
    ids.push(writeDoc('duplicated', i, text, { ...p, __canary: tok }, ['name','dob','mrn']));
  }
  return ids;
}

// ─────────────────────────────────────────────────────────────
// Category F — Unlabeled PHI
// PHI present without any label context. Tests the worst case for
// label-based redaction (relies on pattern-only rules + server NER).
// ─────────────────────────────────────────────────────────────
function buildUnlabeled(n) {
  const ids = [];
  for (let i = 0; i < n; i++) {
    const tok = nextCanary();
    const p = phiSet(tok);
    const text =
`Visit Summary

${p.name}
${p.dob}
${p.address}
${p.phone}
${p.email}
${p.mrn}
${p.insurance}
${p.ssn}
${p.account}

Age ${p.age}
Reason for visit: acute bronchitis.
Plan: rest, fluids, follow up if not improving.`;
    ids.push(writeDoc('unlabeled', i, text, { ...p, __canary: tok }, ALL_CLASSES));
  }
  return ids;
}

// ─────────────────────────────────────────────────────────────
// Run all categories.
// ─────────────────────────────────────────────────────────────
const counts = {
  ocr:        buildOcr(10).length,
  narrative:  buildNarrative(10).length,
  typos:      buildTypos(10).length,
  multiline:  buildMultiline(10).length,
  duplicated: buildDuplicated(10).length,
  unlabeled:  buildUnlabeled(10).length,
};

const manifest = {
  generated_at: new Date().toISOString(),
  description: 'Adversarial stress corpus — realistic messiness to probe redaction limits',
  categories: counts,
  total: Object.values(counts).reduce((a, b) => a + b, 0),
};
fs.writeFileSync(path.join(STRESS_ROOT, 'manifest.json'), JSON.stringify(manifest, null, 2));

console.log(`Stress corpus generated: ${manifest.total} documents across ${Object.keys(counts).length} categories`);
for (const [cat, n] of Object.entries(counts)) console.log(`  ${cat.padEnd(12)} ${n}`);
console.log(`Root: ${STRESS_ROOT}`);
