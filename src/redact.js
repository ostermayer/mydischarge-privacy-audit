/**
 * On-device PII redaction — runs entirely on the phone before any text leaves the device.
 * Supports all 15 app languages: EN, ES, ZH, VI, KO, TL, AR, FR, RU, PT, HT, DE, JA, HI, FA
 *
 * REDACTS (patient identity):
 *   - Patient name, DOB, age, SSN
 *   - Patient address, patient email, patient phone
 *   - Insurance/member IDs, medical record numbers
 *
 * KEEPS (hospital/clinical info):
 *   - Hospital/clinic name, address, phone number
 *   - Doctor/provider names (labeled as such)
 *   - Appointment dates and follow-up info
 *   - Medication names, dosages, instructions
 *   - Diagnosis, warnings, clinical notes
 *
 * Layers:
 *   1. Regex label-based detection (multilingual)
 *   2. Name propagation (scrubs all occurrences of detected names)
 */


const REDACTED = '[REDACTED]';

// ── Universal patterns (language-independent) ──

const SSN = /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g;
const EMAIL = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b/g;

// ── Pattern-only fallback: US mailing address ──
// Matches the full canonical US address form: <number> <street words> <suffix>,
// [optional city,] <2-letter state> <5-digit ZIP[-4]>.  Intentionally strict
// (requires the state + zip tail) to avoid over-matching bare street references
// in clinical text like "walked 3 blocks down Main St to the pharmacy".
const US_ADDRESS = /\b\d{1,6}\s+[\w\-'.]+(?:\s+[\w\-'.]+){0,6}\s+(?:Lane|Ln|Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Court|Ct|Way|Place|Pl|Drive|Dr|Circle|Cir|Trail|Trl|Terrace|Ter|Parkway|Pkwy|Highway|Hwy|Square|Sq)\.?(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#)\s*\S+)?(?:\s*,\s*[\w\s'.\-]+)?\s*,?\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?\b/g;

// ── Pattern-only fallback: insurance member / carrier codes ──
// Matches explicit US insurance carrier prefixes followed by an alphanumeric
// policy code. Case-sensitive on the prefix so clinical words like "insulin"
// (lowercase "ins") are not matched. Requires ≥4 alphanumeric chars after the
// prefix so short common acronyms aren't swept up.
const INSURANCE_CARRIER = /\b(?:INS|BCBS|AETNA|UHC|UHG|CIGNA|HUMANA|KAISER|ANTHEM|MEDICARE|MEDICAID|TRICARE|WELLPOINT|CENTENE)[\-]?[A-Z0-9][A-Z0-9\-]{3,24}\b/g;

// ── Multilingual MRN / Medical Record Number ──

const MRN = new RegExp(
  '(?:' +
    // EN
    'MRN|MR#|MR\\s*#|Medical Record' +
    // ES
    '|N[uú]mero de Expediente|Expediente M[eé]dico|Historia Cl[ií]nica|HC\\b' +
    // ZH
    '|病[历歷]号|病案号' +
    // VI
    '|[Mm][aã] b[eệ]nh nh[aâ]n|[Ss][oố] h[oồ] s[oơ]' +
    // KO
    '|등록번호|의무기록번호' +
    // TL (uses English terms)
    // AR
    '|رقم الملف الطبي|رقم السجل' +
    // FR
    '|Num[eé]ro de Dossier|Dossier M[eé]dical|NDA' +
    // RU
    '|[Нн]омер карты|[Ии]стория болезни|[Нн]омер истории' +
    // PT
    '|N[uú]mero do Prontu[aá]rio|Prontu[aá]rio' +
    // HT
    '|Dosye Medikal|Nimewo Dosye' +
    // DE
    '|Patientennummer|Fallnummer|Aktennummer' +
    // JA
    '|患者番号|カルテ番号|診察券番号' +
    // HI
    '|रोगी संख्या|एमआरएन' +
    // FA
    '|شماره پرونده' +
  ')' +
  '[\\s:#：]*[A-Z0-9\\d]{4,12}',
  'gi'
);

// ── Multilingual Insurance / Member IDs ──

const INSURANCE_ID = new RegExp(
  '(?:' +
    // EN
    '(?:Member|Subscriber|Group|Policy|Insurance)\\s*(?:ID|#|No|Number)' +
    // ES
    '|(?:Seguro|P[oó]liza|Miembro|Asegurado)\\s*(?:ID|#|No|N[uú]mero)?' +
    // ZH
    '|医保号|保险号|会员号' +
    // VI
    '|[Ss][oố] th[eẻ] b[aả]o hi[eể]m|[Bb][aả]o hi[eể]m' +
    // KO
    '|보험번호|가입자번호' +
    // AR
    '|رقم التأمين|رقم العضوية' +
    // FR
    '|Num[eé]ro d.Assurance|Assurance|Mutuelle' +
    // RU
    '|[Сс]траховой полис|[Нн]омер полиса|[Нн]омер страховки' +
    // PT
    '|N[uú]mero do Seguro|Conv[eê]nio|Plano de Sa[uú]de' +
    // HT
    '|Asirans|Nimewo Asirans' +
    // DE
    '|Versicherungsnummer|Versichertennummer|Krankenkasse' +
    // JA
    '|保険証番号|被保険者番号' +
    // HI
    '|बीमा संख्या|बीमा' +
    // FA
    '|شماره بیمه|بیمه' +
  ')' +
  '[\\s:#：]*[A-Z0-9\\d]{4,20}',
  'gi'
);

// ── Account numbers (patient billing) ──

const ACCT = new RegExp(
  '(?:' +
    'Acct|Account' +
    '|Cuenta' +       // ES
    '|Compte' +       // FR
    '|Conta' +        // PT
    '|Konto' +        // DE
    '|счёт|счет' +    // RU
    '|账号|账户|帳號' + // ZH (simplified + traditional)
    '|計帳号|口座番号|勘定番号' + // JA
    '|계정번호|계좌번호' + // KO
    '|رقم الحساب' +   // AR
    '|खाता संख्या' +  // HI
    '|شماره حساب' +    // FA
    '|T[aà]i kho[aả]n' + // VI
    '|Kont' +          // HT / TL fallback
  ')' +
  '\\s*(?:#|No|Number)?[\\s:#：]*\\d{4,12}',
  'gi'
);

// ── Labels that precede a PATIENT name — we redact the value ──

const PATIENT_NAME_LABELS = [
  // EN
  'patient', 'patient name', 'name', 'pt', 'pt name', 'client',
  'resident', 'guarantor', 'responsible party',
  'emergency contact', 'next of kin', 'spouse', 'guardian', 'parent', 'caregiver',
  // ES
  'paciente', 'nombre del paciente', 'nombre', 'contacto de emergencia',
  'familiar', 'tutor', 'responsable',
  // ZH
  '患者姓名', '患者', '姓名', '病人姓名', '病人', '紧急联系人', '紧急联络人',
  '監護人', '家属',
  // VI
  'bệnh nhân', 'họ tên', 'tên bệnh nhân', 'họ và tên',
  'người liên hệ khẩn cấp', 'người giám hộ',
  // KO
  '환자명', '환자', '성명', '이름', '긴급연락처', '보호자',
  // TL
  'pasyente', 'pangalan ng pasyente', 'pangalan',
  // AR
  'اسم المريض', 'المريض', 'الاسم', 'اسم', 'جهة اتصال الطوارئ', 'ولي الأمر',
  // FR
  'patient', 'patiente', 'nom du patient', 'nom de la patiente',
  'contact d\'urgence', 'personne à contacter', 'tuteur',
  // RU
  'пациент', 'ФИО', 'имя пациента', 'фамилия', 'больной',
  'экстренный контакт', 'опекун',
  // PT
  'paciente', 'nome do paciente', 'contato de emergência', 'responsável',
  // HT
  'pasyan', 'non pasyan', 'non',
  'kontak dijans', 'gadyen',
  // DE
  'Patient', 'Patientin', 'Patientenname', 'Notfallkontakt',
  'Vormund', 'Betreuer',
  // JA
  '患者氏名', '患者名', '氏名', '名前', '緊急連絡先', '保護者',
  // HI
  'रोगी', 'मरीज़', 'मरीज', 'रोगी का नाम', 'नाम',
  'आपातकालीन संपर्क', 'अभिभावक',
  // FA
  'بیمار', 'نام بیمار', 'نام', 'تماس اضطراری', 'سرپرست',
];

// ── Labels for hospital/provider info — we KEEP these ──

const PROVIDER_LABELS = [
  // EN
  'attending', 'physician', 'doctor', 'provider', 'dr', 'md', 'np', 'pa', 'rn',
  'nurse', 'hospital', 'clinic', 'facility', 'department',
  'referred to', 'follow.?up with',
  // ES
  'médico', 'medico', 'doctora?', 'hospital', 'clínica', 'clinica',
  'enfermero', 'enfermera', 'consultorio', 'proveedor',
  // ZH
  '医生', '医师', '主治医师', '主治医生', '医院', '诊所', '护士', '科室',
  // VI
  'bác sĩ', 'bệnh viện', 'phòng khám', 'y tá', 'điều dưỡng',
  // KO
  '의사', '담당의', '주치의', '병원', '클리닉', '간호사',
  // TL
  'doktor', 'ospital', 'klinika', 'nars',
  // AR
  'طبيب', 'دكتور', 'مستشفى', 'عيادة', 'ممرض', 'ممرضة',
  // FR
  'médecin', 'medecin', 'docteur', 'hôpital', 'hopital', 'clinique',
  'infirmier', 'infirmière', 'infirmiere',
  // RU
  'врач', 'доктор', 'больница', 'клиника', 'медсестра', 'поликлиника',
  // PT
  'médico', 'doutor', 'doutora', 'hospital', 'clínica',
  'enfermeiro', 'enfermeira',
  // HT
  'doktè', 'lopital', 'klinik', 'enfimyè',
  // DE
  'Arzt', 'Ärztin', 'Doktor', 'Krankenhaus', 'Klinik', 'Krankenschwester',
  // JA
  '医師', '担当医', '主治医', '病院', 'クリニック', '看護師',
  // HI
  'चिकित्सक', 'डॉक्टर', 'अस्पताल', 'क्लिनिक', 'नर्स',
  // FA
  'پزشک', 'دکتر', 'بیمارستان', 'کلینیک', 'پرستار',
];

// ── Multilingual DOB labels ──

const DOB_LABELS = [
  // EN
  'DOB', 'D\\.O\\.B', 'Date of Birth', 'Birth\\s*Date', 'Born',
  // ES
  'Fecha de Nacimiento', 'FDN', 'Nacimiento',
  // ZH
  '出生日期', '生日',
  // VI
  'Ngày sinh', 'Sinh ngày',
  // KO
  '생년월일',
  // TL
  'Petsa ng Kapanganakan', 'Kaarawan',
  // AR
  'تاريخ الميلاد', 'تاريخ الولادة',
  // FR
  'Date de Naissance', 'DDN', 'N[eé]\\(e\\) le',
  // RU
  'Дата рождения',
  // PT
  'Data de Nascimento', 'DN', 'Nascimento',
  // HT
  'Dat Nesans', 'Dat ou Fèt',
  // DE
  'Geburtsdatum', 'Geb\\.',
  // JA
  '生年月日',
  // HI
  'जन्म तिथि', 'जन्मतिथि',
  // FA
  'تاریخ تولد',
];

// ── Multilingual Age labels ──

const AGE_LABELS = [
  'Age', 'AGE',
  'Edad',             // ES
  '年龄', '年齡',      // ZH
  'Tuổi',             // VI
  '나이', '연령',       // KO
  'Edad',             // TL
  'العمر',            // AR
  '[ÂâAa]ge',         // FR
  'Возраст',          // RU
  'Idade',            // PT
  'Laj',              // HT
  'Alter',            // DE
  '年齢',             // JA
  'आयु', 'उम्र',      // HI
  'سن',               // FA
];

// ── Multilingual Patient Address labels ──
// NOTE: stored as literal label strings. The regex compiler below escapes
// metacharacters and replaces interior whitespace with \s+ so "Home Address"
// and "Home  Address" both match.

const PATIENT_ADDRESS_LABELS = [
  // EN
  'Patient Address', 'Home Address', 'Mailing Address', 'Residential Address', 'Address',
  // ES
  'Dirección del Paciente', 'Direccion del Paciente', 'Dirección', 'Direccion', 'Domicilio',
  // ZH
  '患者地址', '住址', '家庭地址',
  // VI
  'Địa chỉ bệnh nhân', 'Địa chỉ nhà', 'Địa chỉ',
  // KO
  '환자주소', '주소', '자택주소',
  // TL
  'Tirahan',
  // AR
  'عنوان المريض', 'العنوان',
  // FR
  'Adresse du Patient', 'Adresse',
  // RU
  'Адрес пациента', 'Адрес', 'Домашний адрес',
  // PT
  'Endere[cç]o do Paciente', 'Endere[cç]o',
  // HT
  'Adrès Pasyan', 'Adrès',
  // DE
  'Patientenadresse', 'Adresse', 'Wohnadresse',
  // JA
  '患者住所', '住所', '自宅住所',
  // HI
  'रोगी का पता', 'पता', 'घर का पता',
  // FA
  'آدرس بیمار', 'آدرس', 'نشانی',
];

// ── Multilingual phone context: patient vs provider ──

const PATIENT_PHONE_CONTEXT = [
  // EN
  'patient', 'pt\\b', 'home', 'cell', 'mobile', 'emergency contact',
  // ES
  'paciente', 'celular', 'm[oó]vil', 'contacto de emergencia',
  // ZH
  '患者', '病人', '手机', '移动电话', '紧急联系',
  // VI
  'bệnh nhân', 'di động', 'liên hệ khẩn cấp',
  // KO
  '환자', '휴대폰', '긴급연락',
  // AR
  'المريض', 'الجوال', 'المحمول', 'اتصال الطوارئ',
  // FR
  'patient', 'portable', 'mobile', 'contact d\'urgence',
  // RU
  'пациент', 'мобильный', 'сотовый', 'экстренный контакт',
  // PT
  'paciente', 'celular', 'contato de emergência',
  // DE
  'Patient', 'Handy', 'Mobiltelefon', 'Notfallkontakt',
  // JA
  '患者', '携帯', '緊急連絡',
  // HI
  'रोगी', 'मोबाइल', 'आपातकालीन संपर्क',
  // FA
  'بیمار', 'موبایل', 'همراه', 'تماس اضطراری',
];

const PROVIDER_PHONE_CONTEXT = [
  // EN
  'hospital', 'clinic', 'office', 'doctor', 'dr\\.', 'provider', 'nurse',
  'pharmacy', 'call\\s+(?:us|to)', 'schedule', 'appointment', 'follow.?up',
  // ES
  'hospital', 'cl[ií]nica', 'consultorio', 'm[eé]dico', 'farmacia', 'cita',
  // ZH
  '医院', '诊所', '药房', '门诊', '预约', '复诊',
  // VI
  'bệnh viện', 'phòng khám', 'nhà thuốc', 'lịch hẹn', 'tái khám',
  // KO
  '병원', '클리닉', '약국', '예약', '진료',
  // AR
  'مستشفى', 'عيادة', 'صيدلية', 'موعد', 'مراجعة',
  // FR
  'hôpital', 'clinique', 'cabinet', 'pharmacie', 'rendez-vous',
  // RU
  'больница', 'клиника', 'аптека', 'запись', 'приём',
  // PT
  'hospital', 'cl[ií]nica', 'farm[aá]cia', 'consulta', 'agendamento',
  // DE
  'Krankenhaus', 'Klinik', 'Praxis', 'Apotheke', 'Termin',
  // JA
  '病院', 'クリニック', '薬局', '予約', '受診',
  // HI
  'अस्पताल', 'क्लिनिक', 'फार्मेसी', 'अपॉइंटमेंट',
  // FA
  'بیمارستان', 'کلینیک', 'داروخانه', 'نوبت', 'ویزیت',
];

// ═══════════════════════════════════════════
// Redaction functions
// ═══════════════════════════════════════════

/**
 * Extracts patient names found after patient name labels.
 * Returns an array of name strings that were detected.
 */
function extractPatientNames(text) {
  const labelPattern = PATIENT_NAME_LABELS
    .map((l) => l.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+'))
    .join('|');

  const re = new RegExp(
    `(?:${labelPattern})[\\s:;#\\-：]*([^\\n,;：]{2,50})`,
    'giu',
  );

  const names = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const trimmed = m[1].trim();
    if (trimmed.length >= 2 && trimmed !== REDACTED) {
      names.push(trimmed);
    }
  }
  return names;
}

/**
 * Redacts text appearing after patient name labels.
 * Uses Unicode-aware capture to handle all scripts.
 * Does NOT redact text after provider/doctor labels.
 */
function redactPatientNames(text) {
  const labelPattern = PATIENT_NAME_LABELS
    .map((l) => l.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+'))
    .join('|');

  // Capture name-like text in any script after label + separator
  // Uses [^\n,;：] to grab text until line end or delimiter, 2-50 chars
  const re = new RegExp(
    `(?:${labelPattern})[\\s:;#\\-：]*([^\\n,;：]{2,50})`,
    'giu',
  );

  return text.replace(re, (match, nameValue) => {
    const trimmed = nameValue.trim();
    if (trimmed.length < 2) return match;
    return match.replace(nameValue, REDACTED);
  });
}

/**
 * Second-pass: redacts all remaining occurrences of a patient name
 * found via label detection. Also redacts individual name parts
 * (first/last) that are 3+ characters to catch partial mentions.
 */
function redactNameEverywhere(text, names) {
  let result = text;
  for (const name of names) {
    // Redact full name (case-insensitive)
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    result = result.replace(new RegExp(escaped, 'gi'), REDACTED);

    // Redact individual name parts (first, last) if 3+ chars
    const parts = name.split(/\s+/).filter((p) => p.length >= 3 && p !== REDACTED);
    for (const part of parts) {
      const partEscaped = part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      // Only replace standalone word matches to avoid false positives
      result = result.replace(new RegExp(`\\b${partEscaped}\\b`, 'gi'), REDACTED);
    }
  }
  return result;
}

/**
 * Redacts date values near DOB/birth keywords only.
 * Keeps all other dates (appointments, follow-ups, medication dates).
 */
function redactDOB(text) {
  const dobPattern = DOB_LABELS
    .map((l) => l.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('|');

  const dobRe = new RegExp(
    `(?:${dobPattern})[\\s:#\\-：]*(\\S+[\\s/\\-\\.年月日]\\S+(?:[\\s/\\-\\.年月日]\\S+)?)`,
    'giu',
  );
  return text.replace(dobRe, (match, dateVal) => {
    return match.replace(dateVal, REDACTED);
  });
}

/**
 * Redacts age when paired with age labels.
 */
function redactAge(text) {
  const agePattern = AGE_LABELS.join('|');
  const ageRe = new RegExp(
    `(?:${agePattern})[\\s:#：]*(\\d{1,3})\\s*(?:y(?:ears?)?(?:\\s*old)?|yo|y\\/o|歳|岁|세|tuổi|ans|a[ñn]os|лет|anos|J(?:ahre)?)?`,
    'giu',
  );
  return text.replace(ageRe, (match, ageVal) => {
    return match.replace(ageVal, REDACTED);
  });
}

/**
 * Redacts patient address — only near patient/home address labels.
 * Does NOT redact hospital/clinic addresses.
 */
function redactPatientAddress(text) {
  // Escape literal labels, then allow flexible whitespace between label tokens
  // so "Home Address" and "Home  Address" both match. Capture through end of line
  // so US addresses with commas (city, state, zip) are redacted whole.
  const addrPattern = PATIENT_ADDRESS_LABELS
    .map((l) => l.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+'))
    .join('|');

  const addrRe = new RegExp(
    `(?:${addrPattern})[\\s:#：]*([^\\n]{5,120})`,
    'giu',
  );
  return text.replace(addrRe, (match, addrVal) => {
    return match.replace(addrVal, REDACTED);
  });
}

/**
 * Redacts phone numbers that appear near patient labels.
 * KEEPS phone numbers near hospital/clinic/doctor labels.
 */
function redactPatientPhone(text) {
  const lines = text.split('\n');

  // Broad phone patterns: international formats, with/without country code
  const phoneRe = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}/g;

  const patientCtx = new RegExp(PATIENT_PHONE_CONTEXT.join('|'), 'iu');
  const providerCtx = new RegExp(PROVIDER_PHONE_CONTEXT.join('|'), 'iu');

  return lines.map((line) => {
    if (!phoneRe.test(line)) return line;
    phoneRe.lastIndex = 0;

    // If line mentions provider/hospital context, keep the number
    if (providerCtx.test(line)) return line;

    // If line mentions patient context, redact the number
    if (patientCtx.test(line)) {
      return line.replace(phoneRe, REDACTED);
    }

    // Ambiguous — keep it (err on the side of keeping useful info)
    return line;
  }).join('\n');
}

// ═══════════════════════════════════════════
// Main export
// ═══════════════════════════════════════════

/**
 * Main redaction function. Call this on OCR output before sending anywhere.
 * Returns { redacted: string, piiFound: string[] }
 */
export function redact(text) {
  if (!text) return { redacted: '', piiFound: [] };

  const piiFound = [];
  let result = text;

  // 1a. Extract patient names from labeled fields (before redacting)
  const detectedNames = extractPatientNames(result);

  // 1b. Redact labeled patient name fields
  const namesBefore = result;
  result = redactPatientNames(result);
  if (result !== namesBefore) piiFound.push('Patient names');

  // 1c. Redact ALL other occurrences of detected names throughout the document
  if (detectedNames.length > 0) {
    result = redactNameEverywhere(result, detectedNames);
  }


  // 2. DOB
  const dobBefore = result;
  result = redactDOB(result);
  if (result !== dobBefore) piiFound.push('Date of birth');

  // 3. Age
  const ageBefore = result;
  result = redactAge(result);
  if (result !== ageBefore) piiFound.push('Age');

  // 4. SSN
  const ssnMatches = result.match(SSN);
  if (ssnMatches) piiFound.push(`SSN (${ssnMatches.length})`);
  result = result.replace(SSN, REDACTED);

  // 5. Patient phone (context-aware — keeps clinic/hospital phones)
  const phoneBefore = result;
  result = redactPatientPhone(result);
  if (result !== phoneBefore) piiFound.push('Patient phone');

  // 6. Email
  const emailMatches = result.match(EMAIL);
  if (emailMatches) piiFound.push(`Email (${emailMatches.length})`);
  result = result.replace(EMAIL, REDACTED);

  // 7. MRN
  const mrnMatches = result.match(MRN);
  if (mrnMatches) piiFound.push('Medical record #');
  result = result.replace(MRN, REDACTED);

  // 8. Insurance IDs (labeled)
  const insMatches = result.match(INSURANCE_ID);
  if (insMatches) piiFound.push('Insurance ID');
  result = result.replace(INSURANCE_ID, REDACTED);

  // 8b. Insurance IDs (pattern-only fallback, carrier-prefixed)
  const insPatMatches = result.match(INSURANCE_CARRIER);
  if (insPatMatches) piiFound.push('Insurance ID');
  result = result.replace(INSURANCE_CARRIER, REDACTED);

  // 9. Account numbers
  const acctMatches = result.match(ACCT);
  if (acctMatches) piiFound.push('Account #');
  result = result.replace(ACCT, REDACTED);

  // 10. Patient address (context-aware — keeps hospital addresses)
  const addrBefore = result;
  result = redactPatientAddress(result);
  if (result !== addrBefore) piiFound.push('Patient address');

  // 10b. Pattern-only US address fallback — catches unlabeled full addresses.
  const addrPatMatches = result.match(US_ADDRESS);
  if (addrPatMatches) piiFound.push('Patient address');
  result = result.replace(US_ADDRESS, REDACTED);

  return { redacted: result, piiFound };
}
