// Synthetic PHI pool.
// Each PHI value embeds a canary token "ZQK<id>" (6-char uppercase, doc-unique)
// so leakage can be grep-detected without false positives against clinical text.
//
// All values are deliberately synthetic — no real names, SSNs, MRNs, etc.
// Formatting matches realistic PHI to exercise redact.js regexes.

import seedrandom from 'seedrandom';

export const CANARY_PREFIX = 'ZQK';

// Build a 7-char canary: ZQK + 4-digit zero-padded serial.
export function canaryToken(serial) {
  return `${CANARY_PREFIX}${String(serial).padStart(4, '0')}`;
}

// Generate a per-document canary set. Each PHI value embeds the doc token.
export function buildPhiSet(docSerial, rng) {
  const tok = canaryToken(docSerial);

  // Synthetic first/last names with canary embedded as a middle initial suffix.
  // Label-based redaction fires on "Patient Name:" prefix so the name form itself
  // can be any realistic string — we inject the canary in a surname suffix so
  // post-redaction grep catches any leaked fragment.
  const firstNames = ['Ximena', 'Bartholomew', 'Ingrid', 'Kwame', 'Saoirse', 'Tariq',
                      'Yumiko', 'Dashiell', 'Priyanka', 'Octavio', 'Beatriz', 'Aleksandr'];
  const lastNames  = ['Quetzalcoatl', 'Vranjevic', 'Oduya', 'Mogensen', 'Chakrabarti',
                      'Hvidberg', 'Papadimitriou', 'Tchaikovsky', 'Ashworth', 'Bergström'];

  const first = pick(firstNames, rng);
  const last  = pick(lastNames, rng);
  // Append canary as a unique surname suffix: "Quetzalcoatl-ZQK0042"
  const fullName = `${first} ${last}-${tok}`;

  // DOB — month/day arbitrary, year encodes canary serial modulo 100 offset by 1900.
  // Stored as literal string for grep.
  const dobMonth = 1 + Math.floor(rng() * 12);
  const dobDay   = 1 + Math.floor(rng() * 28);
  const dobYear  = 1930 + (docSerial % 70);
  const dobLiteral = `${String(dobMonth).padStart(2, '0')}/${String(dobDay).padStart(2, '0')}/${dobYear}`;
  const dobCanary  = `DOB-${tok}`;  // also embed a grep-able form near label

  // Age — uses a high but plausible value; embeds canary via following comment.
  const ageLiteral = String(50 + (docSerial % 40));
  const ageCanary  = `AGE-${tok}`;

  // SSN — 900-series is reserved/invalid. Encode serial in last 4 digits.
  const ssnLiteral = `900-${String((docSerial % 90) + 10).padStart(2, '0')}-${String(docSerial).padStart(4, '0')}`;
  const ssnCanary  = `SSN-${tok}`;

  // Phone — 555-01xx is the North American reserved "fictitious" range.
  // Use proper 3-3-4 format so the phone-class regex is the rule under test
  // (3-2-4 format would coincidentally match the SSN regex and confound the eval).
  const phoneLiteral = `555-010-${String(docSerial).padStart(4, '0')}`;

  // Email — reserved .invalid TLD.
  const emailLiteral = `canary-${tok.toLowerCase()}@example.invalid`;

  // MRN — alphanumeric >=4 chars; embed canary directly.
  const mrnLiteral = `MRN${tok}`;

  // Insurance ID
  const insLiteral = `INS${tok}XYZ9`;

  // Account number — digits 4-12.
  const acctLiteral = `9${String(docSerial).padStart(7, '0')}`;
  const acctCanary  = `ACCT-${tok}`;

  // Address — US format with canary in street name.
  const addrLiteral = `${1 + docSerial} Canary-${tok} Lane, Testville, TX 77000`;

  return {
    canaryToken: tok,
    fields: [
      { class: 'name',      literal: fullName,     canary: tok, required: true },
      { class: 'dob',       literal: dobLiteral,   canary: tok, required: true, extra: dobCanary },
      { class: 'age',       literal: ageLiteral,   canary: tok, required: false, extra: ageCanary },
      { class: 'ssn',       literal: ssnLiteral,   canary: tok, required: true, extra: ssnCanary },
      { class: 'phone',     literal: phoneLiteral, canary: tok, required: true },
      { class: 'email',     literal: emailLiteral, canary: tok, required: true },
      { class: 'mrn',       literal: mrnLiteral,   canary: tok, required: true },
      { class: 'insurance', literal: insLiteral,   canary: tok, required: true },
      { class: 'account',   literal: acctLiteral,  canary: tok, required: false, extra: acctCanary },
      { class: 'address',   literal: addrLiteral,  canary: tok, required: true },
    ],
  };
}

// Provider info that should be KEPT after redaction (specificity measurement).
export function buildProviderInfo(docSerial, rng) {
  const hospitals = ['Memorial Hermann Texas Medical Center', 'Lyndon B Johnson Hospital',
                     'Ben Taub General Hospital', 'UT Physicians Clinic',
                     'Harris Health East Clinic', 'Bayshore Medical Center'];
  const doctors = ['Dr. Ostermayer', 'Dr. Power', 'Dr. Fischer', 'Dr. Luber',
                   'Dr. Rodriguez', 'Dr. Patel', 'Dr. Nguyen'];
  const drugs = ['amoxicillin 500 mg', 'ibuprofen 400 mg', 'metoprolol 25 mg',
                 'albuterol inhaler', 'acetaminophen 650 mg', 'ondansetron 4 mg'];
  const diagnoses = ['acute otitis media', 'community-acquired pneumonia',
                     'uncomplicated cystitis', 'acute bronchitis',
                     'musculoskeletal strain', 'viral gastroenteritis'];

  return {
    hospital:       pick(hospitals, rng),
    hospitalPhone: '713-500-7878',   // UTHealth switchboard, public
    doctor:         pick(doctors, rng),
    medication:     pick(drugs, rng),
    diagnosis:      pick(diagnoses, rng),
    appointmentDate: `${1 + Math.floor(rng() * 12)}/${1 + Math.floor(rng() * 28)}/2026`,
  };
}

function pick(arr, rng) { return arr[Math.floor(rng() * arr.length)]; }
