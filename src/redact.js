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
 *   3. Fail-closed heuristics for unlabeled PHI: title-case/all-caps name
 *      sweep (Unicode Latin), CJK/Hangul header names, chat self-
 *      identification phrases, header dates (numeric + spelled-out),
 *      per-number phone context, high-risk identifier shapes
 */


const REDACTED = '[REDACTED]';

// ── Universal patterns (language-independent) ──

// Space/dash separators only — \s would let an SSN-shaped match span newlines
// and merge unrelated dose lines ("Take 325\n81 5000 units") into one token.
const SSN = /\b\d{3}[  -]?\d{2}[  -]?\d{4}\b/g;
// RFC-bounded quantifiers — the unbounded local part is O(n²) on long dashed
// runs (same fix as the proxy twin).
const EMAIL = /\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b/g;
const DATE_VALUE = /\b(?:\d{1,2}[\/.\-]\d{1,2}[\/.\-](?:\d{2}|\d{4})|(?:19|20)\d{2}[\/.\-]\d{1,2}[\/.\-]\d{1,2})\b/g;
// Spelled-out dates (English + Spanish month names, year required). Only ever
// applied in DOB/header contexts so follow-up dates like "March 25, 2026" in
// clinical sections survive.
const MONTH_NAME = String.raw`(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|setiembre|octubre|noviembre|diciembre)`;
const TEXT_DATE = new RegExp(
  String.raw`\b(?:${MONTH_NAME})\.?\s+\d{1,2}(?:st|nd|rd|th)?\s*,?\s*(?:19|20)\d{2}\b` +
  String.raw`|\b\d{1,2}(?:st|nd|rd|th)?\s+(?:de\s+)?(?:${MONTH_NAME})\.?\s*(?:,|\bde\b|\bof\b)?\s*(?:19|20)\d{2}\b`,
  'gi',
);
const LONG_NUMERIC_ID = /\b\d{7,}\b/g;
// Candidate token only — the digit-AND-letter requirement is checked in code.
// The previous double-lookahead form rescanned the token at every position,
// an O(n²) stall on long dashed runs.
const ALNUM_IDENTIFIER = /\b[A-Z0-9-]{6,}\b/g;
// Clinical tokens that look like identifiers but must survive the sweep.
const CLINICAL_TOKEN_EXCEPTION = /^(?:COVID-?\d+|ICD-?\d+|CPT-?\d+|SARS-COV-?\d*)$|^\d+(?:MG|MCG|G|ML|MEQ|IU|UNITS?)$/i;

// Latin letter ranges including Latin-1 Supplement, Latin Extended-A and Latin
// Extended Additional (Spanish, Vietnamese, French, Portuguese, German names).
// Explicit ranges instead of \p{..} escapes — Hermes-safe.
const LATIN_UC = String.raw`A-ZÀ-ÖØ-ÞĀ-ſḀ-ỿ`;
const LATIN_LC = String.raw`a-zà-öø-ÿĀ-ſḀ-ỿ`;
const LATIN_LETTER_RE = new RegExp(`[${LATIN_UC}${LATIN_LC}0-9_]`, 'u');

// Fail-closed name detector. This intentionally catches title-case person-like
// strings even when they are not labeled, because patient names often appear in
// headers, greetings, and table layouts without context.
const NAME_WORD = String.raw`(?:[${LATIN_UC}][${LATIN_LC}${LATIN_UC}'’.]{1,30}|[${LATIN_UC}]{2,30})(?:-[A-Z0-9]{3,})?`;
// \b is ASCII-only, so it never matches at an accented edge ("Ángela",
// "José") — a name starting or ending with an accented letter would slip the
// sweep entirely. These explicit Latin-aware lookarounds replace it.
const LATIN_B = String.raw`(?<![${LATIN_UC}${LATIN_LC}0-9_])`;
const LATIN_B_END = String.raw`(?![${LATIN_UC}${LATIN_LC}0-9_])`;
const LIKELY_PERSON_NAME = new RegExp(String.raw`${LATIN_B}${NAME_WORD}(?:\s+${NAME_WORD}){1,3}${LATIN_B_END}`, 'gu');
const INITIAL_LAST_NAME = new RegExp(String.raw`${LATIN_B}[${LATIN_UC}]\.\s*[${LATIN_UC}][${LATIN_LC}${LATIN_UC}'’.-]{1,30}(?:-[A-Z0-9]{3,})?${LATIN_B_END}`, 'gu');
// Leading title-case name sequence — used when a bare "Patient"/"Pt" label is
// followed by free text, so "Patient was advised to rest" is not treated as a
// name field but "Patient Marcus Thornton presented" still redacts the name.
const NAME_SEQ_PREFIX = new RegExp(String.raw`^${NAME_WORD}(?:\s+${NAME_WORD}){0,3}`, 'u');

// Standalone CJK/Hangul header-name heuristic: a header line that is nothing
// but 2-4 Han or Hangul characters is treated as a patient name unless it is a
// common document word. (Full CJK NER is out of scope; labeled CJK names are
// handled by the label passes.)
const CJK_NAME_LINE = /^[一-鿿가-힯]{2,4}$/;
const CJK_DOC_WORDS = /出院|指示|说明|說明|诊断|診斷|摘要|注意|事项|事項|医院|醫院|总结|總結|退院|药物|藥物|진단|약물|병원|퇴원|주의|지시/;

// Document/section vocabulary that must never be treated as a person name.
const DOC_WORD_STOPLIST = new Set([
  'DISCHARGE', 'INSTRUCTIONS', 'SUMMARY', 'EMERGENCY', 'DEPARTMENT', 'VISIT',
  'HOSPITAL', 'MEDICAL', 'CENTER', 'AFTER', 'CARE', 'PATIENT', 'NAME',
  'RECORD', 'NOTES', 'REPORT', 'HOME', 'RETURN', 'WARNING', 'SIGNS',
  'MEDICATIONS', 'FOLLOW', 'INSTRUCCIONES', 'ALTA', 'RESUMEN', 'EMERGENCIA',
  'DEPARTAMENTO', 'VISITA', 'CUIDADO', 'SEGUIMIENTO', 'ADVERTENCIA',
]);

// Medication-shaped lines are exempt from the heuristic name sweep so drug
// names and dosing instructions ("Take Tylenol Extra Strength", "INSULIN 10
// units") are not destroyed. Detected (labeled) names still propagate into
// these lines via redactNameEverywhere.
const MEDICATION_LINE = /\b\d+(?:\.\d+)?\s*(?:mg|mcg|g|ml|units?|tabs?|tablets?|capsules?|puffs?|drops?|sprays?)\b|\b(?:take|tablet|capsule|daily|twice|every|hours?|as\s+needed|prn|with\s+food|by\s+mouth|tome|cada|al\s+d[ií]a|comprimido|tableta)\b/i;

// Chat self-identification: patients type their own names in lowercase, which
// the title-case detector cannot see. Strict introducers always redact the
// following 1-3 word tokens; ambiguous ones ("i'm", "soy") only when the next
// word is not a common symptom/state word.
const NAME_TOKEN = String.raw`[${LATIN_UC}${LATIN_LC}][${LATIN_UC}${LATIN_LC}'’-]+`;
const INTRODUCER_STRICT = new RegExp(
  String.raw`\b(?:my\s+name\s+is|my\s+name'?s|the\s+name\s+is|call\s+me|me\s+llamo|mi\s+nombre\s+es|yo\s+me\s+llamo)\s+(${NAME_TOKEN}(?:\s+${NAME_TOKEN}){0,2})`,
  'giu',
);
const INTRODUCER_AMBIG = new RegExp(
  String.raw`\b(?:i\s*[’']?\s*a?m|soy)\s+(${NAME_TOKEN}(?:\s+${NAME_TOKEN}){1,2})`,
  'giu',
);
const AMBIG_INTRODUCER_STOPWORDS = new Set([
  'feeling', 'having', 'taking', 'getting', 'going', 'still', 'not', 'very',
  'really', 'so', 'just', 'ok', 'okay', 'fine', 'good', 'better', 'worse',
  'sick', 'nauseous', 'dizzy', 'tired', 'sore', 'hurting', 'in', 'on', 'at',
  'supposed', 'confused', 'worried', 'scared', 'allergic', 'diabetic',
  'pregnant', 'bleeding', 'swollen', 'also', 'now', 'here', 'back', 'done',
  'all', 'the', 'una', 'un', 'muy', 'bien', 'mal', 'mejor', 'peor',
  'alérgico', 'alérgica', 'embarazada', 'mareado', 'mareada', 'cansado',
  'cansada', 'enfermo', 'enferma',
]);

const DOB_CONTEXT = /(?:\b(?:d\s*[o0]\s*b|d\.?\s*[o0]\.?\s*b|date\s+of\s+birth|birth\s*date|born|fecha\s+de\s+nacimiento|dob|fdn|ddn|nacimiento|date\s+de\s+naissance|naissance|dat\s+nesans|dat\s+ou\s+f[eè]t|data\s+de\s+nascimento|geburtsdatum)\b|出生日期|生日|ngày\s*sinh|sinh\s*ngày|생년월일|petsa\s+ng\s+kapanganakan|kaarawan|تاريخ الميلاد|تاريخ الولادة|дата рождения|生年月日|जन्म\s*तिथि|जन्मतिथि|تاریخ تولد)/i;
const AGE_CONTEXT = /\b(?:age|edad|tu[oổ]i|âge|idade|alter)\b/i;
const PATIENT_NAME_LINE_CONTEXT = /\b(?:patient\s*name|patient|pt\.?|name|member|subscriber|guarantor|responsible\s+party)\b/i;
const PATIENT_ADDRESS_LINE_CONTEXT = /\b(?:patient\s+address|home\s+address|mailing\s+address|residential\s+address|address|addr|adress|addres)\b/i;
const FOLLOWUP_CONTEXT = /(?:\bfollow\s*up\b|\bfollow-up\b|\bappointment\b|\brandevou\b|\bswivi\b|\bseguimiento\b|\bcita\b|\bsuivi\b|\brendez-vous\b|\bconsulta\b|\bagendamento\b|\bnachsorge\b|\btermin\b|tái\s*khám|lịch\s*hẹn|запись|при[её]м|контроль|复诊|预约|随访|진료|예약|موعد|متابعة|अनुवर्ती)/i;
const CLINICAL_SECTION_START = /(?:\bdiagnosis\b|\bdx\b|\bdiagn[oó]stico\b|\bdyagnostik\b|\bmedication\b|\bmedicine\b|\bmedikaman\b|\bmedicamento\b|\brx\b|\bplan\b|\breason\s+for\s+visit\b|\bfollow\s*up\b|\bfollow-up\b|\breturn\s+to\b|\binstructions\b|\bwarning\b|\battending\b|\bphysician\b|\bdoctor\b|\bprovider\b|\bswivi\b|\bseguimiento\b|\bsuivi\b|\bconsulta\b|\bnachsorge\b|chẩn\s*đoán|thuốc|tái\s*khám|lịch\s*hẹn|диагноз|лекарств|запись|при[её]м|контроль|复诊|预约|随访|진료|예약|موعد|متابعة|निदान|दवा|अनुवर्ती)/i;
const SAFE_PROVIDER_LINE_CONTEXT = /\b(?:attending|physician|doctor|provider|hospital|clinic|facility|department|office|pharmacy|medical\s+center|general\s+hospital|health\s+system|urgent\s+care|referred\s+to|follow\s*.?up\s+with|dr\.?|m[eé]dico|doctora?|hospital|cl[ií]nica|bác sĩ|bệnh viện|phòng khám|médecin|docteur|h[oô]pital|clinique|врач|доктор|больниц[аы]|médico|doutor|doutora|clínica|dokt[eè]|lopital|klinik|arzt|doktor|krankenhaus|klinik)\b|医生|医师|医院|诊所|의사|병원|طبيب|دكتور|مستشفى|عيادة|医師|病院|चिकित्सक|डॉक्टर|अस्पताल|پزشک|دکتر|بیمارستان/i;
const PATIENT_OWNERSHIP_CONTEXT = /\b(?:patient|pt\.?|member|subscriber|guarantor|responsible\s+party|client|resident|home|mailing|residential|paciente|pasyan|пациент)\b|患者|病人|bệnh\s*nhân|환자|المريض|रोगी|بیمار/i;

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
// The bare "INS" prefix additionally requires a digit in the code so ordinary
// all-caps words (INSULIN, INSTRUCTIONS) are never matched.
const INSURANCE_CARRIER = /\b(?:BCBS|AETNA|UHC|UHG|CIGNA|HUMANA|KAISER|ANTHEM|MEDICARE|MEDICAID|TRICARE|WELLPOINT|CENTENE)[\-]?[A-Z0-9][A-Z0-9\-]{3,24}\b|\bINS[\-]?(?=[A-Z0-9\-]*\d)[A-Z0-9][A-Z0-9\-]{3,24}\b/g;

// ── Multilingual MRN / Medical Record Number ──

const MRN = new RegExp(
  '(?:' +
    // EN
    'MRN|MR#|MR\\s*#|Medical Record(?:\\s*(?:Number|No\\.?|Num))?' +
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
    '|Num[eé]ro de Dossier|Dossier M[eé]dical|NDA\\b' +
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
  // Value must contain a digit — otherwise a trailing label word is consumed
  // as the value ("Medical Record Number: 867530" used to match "Number" and
  // leave the actual digits in the text).
  '[\\s:#：]*(?=[A-Z0-9-]{0,11}\\d)[A-Z0-9]{4,12}',
  'gi'
);

// ── Multilingual Insurance / Member IDs ──

// Unambiguous insurance labels — safe to match with a loose value.
const INSURANCE_ID = new RegExp(
  '(?:' +
    // EN
    '(?:Member|Subscriber|Group|Policy|Insurance)\\s*(?:ID|#|No|Number)' +
    // ES (póliza is unambiguous; seguro/miembro/asegurado are everyday words
    // and live in INSURANCE_ID_AMBIGUOUS below)
    '|P[oó]liza\\s*(?:ID|#|No|N[uú]mero)?' +
    // ZH
    '|医保号|保险号|会员号' +
    // VI
    '|[Ss][oố] th[eẻ] b[aả]o hi[eể]m|[Bb][aả]o hi[eể]m' +
    // KO
    '|보험번호|가입자번호' +
    // AR
    '|رقم التأمين|رقم العضوية' +
    // FR
    '|Num[eé]ro d.Assurance' +
    // RU
    '|[Сс]траховой полис|[Нн]омер полиса|[Нн]омер страховки' +
    // PT
    '|N[uú]mero do Seguro|Conv[eê]nio|Plano de Sa[uú]de' +
    // HT
    '|Nimewo Asirans' +
    // DE
    '|Versicherungsnummer|Versichertennummer|Krankenkasse' +
    // JA
    '|保険証番号|被保険者番号' +
    // HI
    '|बीमा संख्या' +
    // FA
    '|شماره بیمه' +
  ')' +
  '[\\s:#：]*[A-Z0-9\\d]{4,20}',
  'gi'
);

// Words that also mean something else in everyday speech ("Es seguro tomar
// ibuprofeno" = "it is safe to take ibuprofen"). These only match as insurance
// labels with an explicit qualifier AND a digit-bearing value.
const INSURANCE_ID_AMBIGUOUS = new RegExp(
  '(?:Seguro|Asegurado|Miembro|Assurance|Mutuelle|Asirans|बीमा|بیمه)' +
  '\\s*(?:ID|#|No\\.?|N[uú]m(?:ero)?|Number)' +
  '[\\s:#：]*(?=[A-Za-z0-9]*\\d)[A-Za-z0-9]{4,20}',
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
  // PT — plain literals: escapedLabelPattern escapes [ and ], so a character
  // class written here would never match.
  'Endereço do Paciente', 'Endereco do Paciente', 'Endereço', 'Endereco',
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
  'hospital', 'clinic', 'facility', 'office', 'doctor', 'dr\\.', 'provider', 'nurse',
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
  'больниц[аы]', 'клиника', 'аптека', 'запись', 'приём',
  // PT
  'hospital', 'cl[ií]nica', 'farm[aá]cia', 'consulta', 'agendamento',
  // HT / TL
  'lopital', 'klinik', 'ospital',
  // DE
  'Krankenhaus', 'Klinik', 'Praxis', 'Apotheke', 'Termin',
  // JA
  '病院', 'クリニック', '薬局', '予約', '受診',
  // HI
  'अस्पताल', 'क्लिनिक', 'फार्मेसी', 'अपॉइंटमेंट',
  // FA
  'بیمارستان', 'کلینیک', 'داروخانه', 'نوبت', 'ویزیت',
];

const PROVIDER_CONTEXT_RE = new RegExp(
  [...PROVIDER_LABELS, ...PROVIDER_PHONE_CONTEXT].join('|'),
  'iu',
);

// ═══════════════════════════════════════════
// Redaction functions
// ═══════════════════════════════════════════

function isBlank(line) {
  return !line || line.trim().length === 0;
}

function escapedLabelPattern(labels) {
  return [...labels]
    .sort((a, b) => b.length - a.length)
    .map((l) => l.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+'))
    .join('|');
}

function isSafeProviderLine(line) {
  return SAFE_PROVIDER_LINE_CONTEXT.test(line) && !PATIENT_OWNERSHIP_CONTEXT.test(line);
}

// Lines exempt from the *heuristic* name sweep (label-detected names still
// propagate into them): provider lines, clinical section lines, dosing lines.
function lineExemptFromNameSweep(line) {
  return isSafeProviderLine(line) || CLINICAL_SECTION_START.test(line) || MEDICATION_LINE.test(line);
}

function containsDocStopWord(candidate) {
  return candidate
    .split(/[\s]+/)
    .some((w) => DOC_WORD_STOPLIST.has(w.replace(/[^A-Za-zÀ-ÖØ-öø-ÿ]/gu, '').toUpperCase()));
}

// Decides whether one LIKELY_PERSON_NAME match on a given line should be
// treated as a name. ALL-CAPS sequences are only names on short lines (real
// all-caps names are standalone header entries; all-caps prose is sheet text).
function isNameSweepCandidate(match, lineTokenCount) {
  if (containsDocStopWord(match)) return false;
  const isAllCaps = match === match.toUpperCase();
  if (isAllCaps && lineTokenCount > 4) return false;
  return true;
}

function lineTokenCount(line) {
  return line.trim().split(/\s+/).filter(Boolean).length;
}

// Case-insensitive whole-word replacement with manual boundaries — \b is
// ASCII-only and fails on names ending in accented letters ("José").
function replaceWordEverywhere(text, word) {
  const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(escaped, 'giu');
  return text.replace(re, (m, offset, str) => {
    const before = offset > 0 ? str[offset - 1] : '';
    const after = offset + m.length < str.length ? str[offset + m.length] : '';
    if (before && LATIN_LETTER_RE.test(before)) return m;
    if (after && LATIN_LETTER_RE.test(after)) return m;
    return REDACTED;
  });
}

function replaceDateValues(line) {
  DATE_VALUE.lastIndex = 0;
  TEXT_DATE.lastIndex = 0;
  const next = line.replace(DATE_VALUE, REDACTED).replace(TEXT_DATE, REDACTED);
  DATE_VALUE.lastIndex = 0;
  TEXT_DATE.lastIndex = 0;
  return next;
}

function hasDateValue(line) {
  DATE_VALUE.lastIndex = 0;
  TEXT_DATE.lastIndex = 0;
  const found = DATE_VALUE.test(line) || TEXT_DATE.test(line);
  DATE_VALUE.lastIndex = 0;
  TEXT_DATE.lastIndex = 0;
  return found;
}

function replaceAlnumIdentifiers(text) {
  return text.replace(ALNUM_IDENTIFIER, (m) =>
    /\d/.test(m) && /[A-Z]/.test(m) && !CLINICAL_TOKEN_EXCEPTION.test(m) ? REDACTED : m,
  );
}

function hasPatientNameLineContext(line) {
  return PATIENT_NAME_LINE_CONTEXT.test(line) && !isSafeProviderLine(line);
}

// Section headers that merely CONTAIN a label word ("Patient Instructions:",
// "Patient Education:") are not value fields — treating them as one wipes the
// first line of the section that follows.
const NON_FIELD_HEADER = /\b(?:instructions?|instrucciones|education|educaci[oó]n|information|informaci[oó]n|summary|resumen|notes?|plan|discharge|alta|history|historia)\b/i;

function standaloneLabel(raw) {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 80) return '';

  const trailingSeparator = trimmed.match(/^(.{1,80}?)[\s：:#;\-]+$/u);
  if (trailingSeparator) {
    const label = trailingSeparator[1].trim();
    return NON_FIELD_HEADER.test(label) ? '' : label;
  }

  // Inline fields such as "Patient Name: Jane Doe" are handled by the inline
  // redactors. This pass is only for OCR layouts where the value is on the
  // next line.
  if (/^[^：:#;\-]{1,80}[：:#;\-]\s*\S/u.test(trimmed)) return '';

  // A bare line with no separator is only a label if it is label-shaped.
  // Narrative sentences ("Patient was advised to rest at home.") must not be
  // treated as field labels, or the following line gets wiped.
  if (trimmed.split(/\s+/).filter(Boolean).length > 4) return '';

  return NON_FIELD_HEADER.test(trimmed) ? '' : trimmed;
}

function looksLikePatientNameValue(value) {
  const trimmed = value.trim();
  if (trimmed.length < 2 || trimmed === REDACTED) return false;
  if (/[：:]/u.test(trimmed)) return false;
  if (/@/.test(trimmed)) return false;
  if (/^\d/.test(trimmed)) return false;
  if (!/[^\d\s,;#\-：:]/u.test(trimmed)) return false;
  DATE_VALUE.lastIndex = 0;
  SSN.lastIndex = 0;
  const hasDate = DATE_VALUE.test(trimmed);
  const hasSsn = SSN.test(trimmed);
  DATE_VALUE.lastIndex = 0;
  SSN.lastIndex = 0;
  return !hasDate && !hasSsn;
}

function redactNextContentLine(lines, startIndex, test = () => true, action = null) {
  for (let j = startIndex + 1; j < lines.length; j++) {
    const candidate = lines[j].trim();
    if (!candidate) continue;
    if (CLINICAL_SECTION_START.test(candidate)) return false;
    // Never consume a follow-up/appointment line: its date is exactly the
    // date the patient must keep.
    if (FOLLOWUP_CONTEXT.test(candidate)) return false;
    if (test(candidate)) {
      const before = lines[j];
      lines[j] = action ? action(lines[j]) : lines[j].replace(/\S.*$/, REDACTED);
      return lines[j] !== before;
    }
    return false;
  }
  return false;
}

function extractMultilinePatientNames(text) {
  const lines = text.split('\n');
  const names = [];
  for (let i = 0; i < lines.length; i++) {
    const label = standaloneLabel(lines[i]);
    if (!label || !hasPatientNameLineContext(label)) continue;
    for (let j = i + 1; j < lines.length; j++) {
      const candidate = lines[j].trim();
      if (!candidate) continue;
      if (CLINICAL_SECTION_START.test(candidate)) break;
      if (looksLikePatientNameValue(candidate) && (LIKELY_PERSON_NAME.test(candidate) || INITIAL_LAST_NAME.test(candidate))) {
        names.push(candidate);
      }
      LIKELY_PERSON_NAME.lastIndex = 0;
      INITIAL_LAST_NAME.lastIndex = 0;
      break;
    }
  }
  return names;
}

function extractLikelyHeaderNames(text) {
  const lines = text.split('\n');
  const names = [];
  const maxHeaderLines = Math.min(lines.length, 16);
  for (let i = 0; i < maxHeaderLines; i++) {
    const line = lines[i];
    if (isBlank(line) || lineExemptFromNameSweep(line)) continue;
    const tokens = lineTokenCount(line);
    let m;
    while ((m = LIKELY_PERSON_NAME.exec(line)) !== null) {
      if (isNameSweepCandidate(m[0], tokens)) names.push(m[0]);
    }
    while ((m = INITIAL_LAST_NAME.exec(line)) !== null) {
      names.push(m[0]);
    }
    LIKELY_PERSON_NAME.lastIndex = 0;
    INITIAL_LAST_NAME.lastIndex = 0;
  }
  return names;
}

function redactMultilineLabeledValues(text) {
  const lines = text.split('\n');
  let changed = false;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const label = standaloneLabel(raw);
    if (!label) continue;

    if (hasPatientNameLineContext(label)) {
      changed = redactNextContentLine(lines, i, (candidate) =>
        looksLikePatientNameValue(candidate) &&
        (LIKELY_PERSON_NAME.test(candidate) || INITIAL_LAST_NAME.test(candidate) || /^[^\d]{2,80}$/u.test(candidate))
      ) || changed;
      LIKELY_PERSON_NAME.lastIndex = 0;
      INITIAL_LAST_NAME.lastIndex = 0;
    }

    if (DOB_CONTEXT.test(label)) {
      // Redact only the date on the value line, not the whole line — the line
      // after a DOB label can carry unrelated OCR-merged content.
      changed = redactNextContentLine(lines, i, (candidate) => hasDateValue(candidate), replaceDateValues) || changed;
    }

    if (AGE_CONTEXT.test(label)) {
      changed = redactNextContentLine(lines, i, (candidate) => /^\d{1,3}\b/.test(candidate)) || changed;
    }

    if (PATIENT_ADDRESS_LINE_CONTEXT.test(label)) {
      let redactingAddressBlock = false;
      for (let j = i + 1; j < Math.min(lines.length, i + 4); j++) {
        if (isBlank(lines[j])) break;
        if (CLINICAL_SECTION_START.test(lines[j])) break;
        if (/\d|,\s*[A-Z]{2}\s+\d{5}\b/.test(lines[j])) {
          lines[j] = lines[j].replace(/\S.*$/, REDACTED);
          changed = true;
          redactingAddressBlock = true;
          continue;
        }
        if (redactingAddressBlock) {
          lines[j] = lines[j].replace(/\S.*$/, REDACTED);
          changed = true;
        }
      }
    }
  }

  return { text: lines.join('\n'), changed };
}

// "LAST, FIRST" header layouts: the labeled value capture stops at the comma,
// so the given name after it has to be picked up separately — but only when
// it is name-shaped and not a following field word
// ("Patient: SMITH, DOB 01/02/1980" must not treat DOB as a name).
const NAME_TAIL_STOPWORD = /^(?:DOB|MRN|SSN|FIN|ACCT|ID|AGE|SEX|M|F)$/i;
function nameCommaTail(rawTail) {
  if (!rawTail) return null;
  const tail = rawTail.replace(/^,\s*/, '').trim();
  if (!tail) return null;
  const m = tail.match(NAME_SEQ_PREFIX);
  if (!m) return null;
  const firstWord = m[0].split(/\s+/)[0];
  if (NAME_TAIL_STOPWORD.test(firstWord) || containsDocStopWord(m[0])) return null;
  return m[0];
}

/**
 * Extracts patient names found after patient name labels.
 * Returns an array of name strings that were detected.
 */
function extractPatientNames(text) {
  const labelPattern = escapedLabelPattern(PATIENT_NAME_LABELS);

  const re = new RegExp(
    `(^|\\n)(\\s*(?:${labelPattern}))([\\s:;#\\-：]+)([^\\n,;：]{2,50})((?:,[^\\S\\n]*[^\\n,;：]{1,40})?)`,
    'giu',
  );

  const names = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const sep = m[3];
    const trimmed = m[4].trim();
    if (!looksLikePatientNameValue(trimmed)) continue;
    if (!/[：:#;\-]/u.test(sep)) {
      // Bare label ("Patient <text>"): only a leading title-case sequence is a
      // name. Capturing a sentence here would poison redactNameEverywhere.
      const prefix = trimmed.match(NAME_SEQ_PREFIX);
      if (prefix) names.push(prefix[0]);
      continue;
    }
    names.push(trimmed);
    const tailName = nameCommaTail(m[5]);
    if (tailName) names.push(tailName);
  }
  return names;
}

/**
 * Redacts text appearing after patient name labels.
 * Uses Unicode-aware capture to handle all scripts.
 * Does NOT redact text after provider/doctor labels.
 */
function redactPatientNames(text) {
  const labelPattern = escapedLabelPattern(PATIENT_NAME_LABELS);

  // Capture name-like text in any script after label + separator
  // Uses [^\n,;：] to grab text until line end or delimiter, 2-50 chars,
  // plus an optional ", First" continuation for LAST, FIRST layouts.
  const re = new RegExp(
    `(^|\\n)(\\s*(?:${labelPattern}))([\\s:;#\\-：]+)([^\\n,;：]{2,50})((?:,[^\\S\\n]*[^\\n,;：]{1,40})?)`,
    'giu',
  );

  return text.replace(re, (match, prefix, label, sep, nameValue, rawTail) => {
    const trimmed = nameValue.trim();
    if (!looksLikePatientNameValue(trimmed)) return match;
    if (!/[：:#;\-]/u.test(sep)) {
      // Bare label followed by free text: redact only a leading title-case
      // name sequence; plain narrative ("Patient was advised...") stays.
      const namePrefix = trimmed.match(NAME_SEQ_PREFIX);
      if (!namePrefix) return match;
      return `${prefix}${label}${sep}${nameValue.replace(namePrefix[0], REDACTED)}${rawTail}`;
    }
    const tailName = nameCommaTail(rawTail);
    const tailOut = tailName ? rawTail.replace(tailName, REDACTED) : rawTail;
    return `${prefix}${label}${sep}${REDACTED}${tailOut}`;
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
    // Redact full name (case-insensitive). Boundary-aware: an unanchored
    // replace would shred substrings — a patient named LEE turns "sleep"
    // into "s[REDACTED]p" across the whole document.
    result = replaceWordEverywhere(result, name);

    // Redact individual name parts (first, last) if 3+ chars.
    // replaceWordEverywhere uses manual boundaries because \b fails on
    // accented final letters ("José").
    const parts = name.split(/\s+/).filter((p) => p.length >= 3 && p !== REDACTED);
    for (const part of parts) {
      result = replaceWordEverywhere(result, part);
    }
  }
  return result;
}

function redactLikelyPersonNames(text) {
  const lines = text.split('\n');
  let changed = false;
  const redacted = lines.map((line) => {
    if (lineExemptFromNameSweep(line)) {
      return line;
    }
    const tokens = lineTokenCount(line);
    let next = line.replace(LIKELY_PERSON_NAME, (m) =>
      isNameSweepCandidate(m, tokens) ? REDACTED : m,
    );
    next = next.replace(INITIAL_LAST_NAME, REDACTED);
    LIKELY_PERSON_NAME.lastIndex = 0;
    INITIAL_LAST_NAME.lastIndex = 0;
    if (next !== line) changed = true;
    return next;
  });
  return { text: redacted.join('\n'), changed };
}

// Chat self-identification ("hi im john smith", "me llamo rosa fuentes").
function redactIntroducedNames(text) {
  let changed = false;
  let result = text.replace(INTRODUCER_STRICT, (match, captured) => {
    changed = true;
    return match.replace(captured, REDACTED);
  });
  result = result.replace(INTRODUCER_AMBIG, (match, captured) => {
    const firstWord = captured.split(/\s+/)[0].toLowerCase();
    if (AMBIG_INTRODUCER_STOPWORDS.has(firstWord)) return match;
    changed = true;
    return match.replace(captured, REDACTED);
  });
  return { text: result, changed };
}

// Standalone 2-4 character Han/Hangul lines in the document header.
function redactCjkHeaderNames(text) {
  const lines = text.split('\n');
  let changed = false;
  const maxHeaderLines = Math.min(lines.length, 16);
  for (let i = 0; i < maxHeaderLines; i++) {
    const trimmed = lines[i].trim();
    if (CJK_NAME_LINE.test(trimmed) && !CJK_DOC_WORDS.test(trimmed)) {
      lines[i] = lines[i].replace(trimmed, REDACTED);
      changed = true;
    }
  }
  return { text: lines.join('\n'), changed };
}

function redactDobContextLines(text) {
  const lines = text.split('\n');
  let changed = false;

  for (let i = 0; i < lines.length; i++) {
    if (DOB_CONTEXT.test(lines[i])) {
      const before = lines[i];
      lines[i] = replaceDateValues(lines[i]);
      if (lines[i] !== before) changed = true;
      // Date-only on the continuation line (see redactMultilineLabeledValues).
      changed = redactNextContentLine(lines, i, (candidate) => hasDateValue(candidate), replaceDateValues) || changed;
    }
  }

  return { text: lines.join('\n'), changed };
}

function redactUnlabeledHeaderDates(text) {
  const lines = text.split('\n');
  let changed = false;
  let inHeader = true;

  for (let i = 0; i < lines.length; i++) {
    if (CLINICAL_SECTION_START.test(lines[i])) inHeader = false;
    if (FOLLOWUP_CONTEXT.test(lines[i])) {
      inHeader = false;
      continue;
    }
    if (!inHeader) continue;

    if (hasDateValue(lines[i])) {
      lines[i] = replaceDateValues(lines[i]);
      changed = true;
    }
  }

  return { text: lines.join('\n'), changed };
}

function redactHighRiskIdentifiers(text) {
  const lines = text.split('\n');
  let changed = false;
  const redacted = lines.map((line) => {
    const providerLine = isSafeProviderLine(line);
    let next = replaceAlnumIdentifiers(line);
    // Keep contiguous 10-11 digit numbers on provider lines — they are clinic
    // phone numbers ("Call the clinic at 7135551234"), not patient IDs.
    next = next.replace(LONG_NUMERIC_ID, (m) =>
      providerLine && /^\d{10,11}$/.test(m) ? m : REDACTED,
    );
    if (next !== line) changed = true;
    return next;
  });
  return { text: redacted.join('\n'), changed };
}

function redactAddressLikeLines(text) {
  // Suffix words that are unambiguous street markers. st/ct/sq/dr/pl are NOT
  // here: they are also clinical abbreviations (ST elevation, CT scan, SQ
  // injection, Dr., PL) and only count inside a full address shape below.
  const streetSuffixSafe = /\b(?:lane|ln|street|avenue|ave|road|rd|boulevard|blvd|court|way|place|drive|circle|cir|trail|trl|terrace|ter|parkway|pkwy|highway|hwy|square)\b/i;
  const streetShapeAmbig = /\b\d{1,6}\s+\S+(?:\s+\S+){0,7}\s+(?:st|ct|sq|dr|pl)\b/i;
  // Bounded quantifiers: the unbounded form was O(n²) on long dashed runs
  // (the class includes '-'), same fix as the proxy twin.
  const cityStateZip = /\b[A-Z][A-Za-z'.-]{0,40}(?:\s+[A-Z][A-Za-z'.-]{0,40}){0,5},\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?\b/;
  const lines = text.split('\n');
  let changed = false;
  const redacted = lines.map((line) => {
    if (isSafeProviderLine(line)) {
      return line;
    }
    // Dosing lines never get the whole-line wipe — "Enoxaparin 40 mg SQ once
    // daily" is clinical content, not an address.
    if (MEDICATION_LINE.test(line)) {
      return line;
    }
    if ((/\d/.test(line) && streetSuffixSafe.test(line)) || streetShapeAmbig.test(line) || cityStateZip.test(line)) {
      changed = true;
      return line.replace(/\S.*$/, REDACTED);
    }
    return line;
  });
  return { text: redacted.join('\n'), changed };
}

function redactUsAddresses(text) {
  const lines = text.split('\n');
  let changed = false;
  const redacted = lines.map((line) => {
    if (isSafeProviderLine(line)) {
      return line;
    }
    const before = line;
    US_ADDRESS.lastIndex = 0;
    const next = line.replace(US_ADDRESS, REDACTED);
    US_ADDRESS.lastIndex = 0;
    if (next !== before) changed = true;
    return next;
  });
  return { text: redacted.join('\n'), changed };
}

/**
 * Redacts date values near DOB/birth keywords only.
 * Keeps all other dates (appointments, follow-ups, medication dates).
 */
function redactDOB(text) {
  return text.split('\n').map((line) => {
    if (!DOB_CONTEXT.test(line)) return line;
    return replaceDateValues(line);
  }).join('\n');
}

/**
 * Redacts age when paired with age labels.
 */
function redactAge(text) {
  const agePattern = AGE_LABELS.join('|');
  const ageRe = new RegExp(
    `(^|[\\n\\r\\s,;|])((?:${agePattern})[\\s:#：]*)(\\d{1,3})\\s*(?:y(?:ears?)?(?:\\s*old)?|yo|y\\/o|歳|岁|세|tuổi|ans|a[ñn]os|лет|anos|J(?:ahre)?)?`,
    'giu',
  );
  return text.replace(ageRe, (match, prefix, label, ageVal) => {
    return `${prefix}${label}${REDACTED}`;
  });
}

function redactNarrativeAge(text) {
  const agePhrase = /\b(1[01]\d|12[0-5]|[1-9]?\d)\s*(years?\s+old|year-old|yo|y\/o)\b/gi;
  const lines = text.split('\n');
  let changed = false;

  const redacted = lines.map((line) => {
    if (!PATIENT_OWNERSHIP_CONTEXT.test(line) && !DOB_CONTEXT.test(line) && !AGE_CONTEXT.test(line)) {
      return line;
    }
    const next = line.replace(agePhrase, `${REDACTED} $2`);
    if (next !== line) changed = true;
    return next;
  });

  return { text: redacted.join('\n'), changed };
}

/**
 * Redacts patient address — only near patient/home address labels.
 * Does NOT redact hospital/clinic addresses.
 */
function redactPatientAddress(text) {
  // Escape literal labels, then allow flexible whitespace between label tokens
  // so "Home Address" and "Home  Address" both match. Capture through end of line
  // so US addresses with commas (city, state, zip) are redacted whole.
  const addrPattern = escapedLabelPattern(PATIENT_ADDRESS_LABELS);

  const addrRe = new RegExp(
    `(^|\\n)(\\s*(?:${addrPattern})[\\s:#：\\-]+)([^\\n]{5,120})`,
    'giu',
  );
  return text.split('\n').map((line) => {
    if (isSafeProviderLine(line)) {
      return line;
    }
    return line.replace(addrRe, (match, prefix, label, addrVal) => {
      return `${prefix}${label}${REDACTED}`;
    });
  }).join('\n');
}

/**
 * Redacts phone numbers that appear near patient labels.
 * KEEPS phone numbers near hospital/clinic/doctor labels.
 */
function findContextCues(line, regex, kind) {
  const cues = [];
  const g = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : `${regex.flags}g`);
  let m;
  while ((m = g.exec(line)) !== null) {
    cues.push({ index: m.index, end: m.index + m[0].length, kind });
    if (m.index === g.lastIndex) g.lastIndex++;
  }
  return cues;
}

/**
 * Redacts phone numbers per-number, not per-line: the nearest context cue on
 * the line decides each number. Two-column OCR layouts routinely merge
 * "Cell: <patient #>  Clinic: <clinic #>" into one line, so a line-level
 * provider whitelist would leak the patient number.
 */
function redactPatientPhone(text) {
  const lines = text.split('\n');

  // Broad phone patterns: international formats, with/without country code
  const phoneRe = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}/g;

  const patientCtx = new RegExp(PATIENT_PHONE_CONTEXT.join('|'), 'iu');
  const providerCtx = new RegExp(PROVIDER_PHONE_CONTEXT.join('|'), 'iu');

  return lines.map((line) => {
    phoneRe.lastIndex = 0;
    if (!phoneRe.test(line)) return line;
    phoneRe.lastIndex = 0;

    const cues = [
      ...findContextCues(line, patientCtx, 'patient'),
      ...findContextCues(line, providerCtx, 'provider'),
    ];

    return line.replace(phoneRe, (match, offset) => {
      let nearestBefore = null;
      let nearestAfter = null;
      for (const cue of cues) {
        if (cue.end <= offset && (!nearestBefore || cue.end > nearestBefore.end)) {
          nearestBefore = cue;
        }
        if (cue.index >= offset + match.length && (!nearestAfter || cue.index < nearestAfter.index)) {
          nearestAfter = cue;
        }
      }
      // A trailing cue only counts when nothing precedes ("555-0182 (cell)").
      const decider = nearestBefore
        || (nearestAfter && nearestAfter.index - (offset + match.length) <= 24 ? nearestAfter : null);
      if (decider && decider.kind === 'provider') return match;
      // Patient cue, or no cue at all: patient data until proven otherwise.
      return REDACTED;
    });
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
  const detectedNames = [
    ...extractPatientNames(result),
    ...extractMultilinePatientNames(result),
    ...extractLikelyHeaderNames(result),
  ];

  // 1aa. Redact values in common multiline layouts, e.g. "Patient Name:\nJohn Smith"
  const multilineBefore = result;
  const multiline = redactMultilineLabeledValues(result);
  result = multiline.text;
  if (multiline.changed && result !== multilineBefore) piiFound.push('Multiline identifiers');

  // 1b. Redact labeled patient name fields
  const namesBefore = result;
  result = redactPatientNames(result);
  if (result !== namesBefore) piiFound.push('Patient names');

  // 1c. Redact ALL other occurrences of detected names throughout the document
  if (detectedNames.length > 0) {
    result = redactNameEverywhere(result, detectedNames);
  }

  // 1d. Fail-closed pass for unlabeled/header names that could identify a patient.
  const likelyNameBefore = result;
  const likelyNames = redactLikelyPersonNames(result);
  result = likelyNames.text;
  if (likelyNames.changed && result !== likelyNameBefore) piiFound.push('Unlabeled names');

  // 1e. Chat self-identification ("hi im john smith", "me llamo rosa fuentes").
  const introduced = redactIntroducedNames(result);
  result = introduced.text;
  if (introduced.changed) piiFound.push('Patient names');

  // 1f. Standalone CJK/Hangul header name lines.
  const cjkNames = redactCjkHeaderNames(result);
  result = cjkNames.text;
  if (cjkNames.changed) piiFound.push('Unlabeled names');

  // 2. DOB
  const dobContextBefore = result;
  const dobContext = redactDobContextLines(result);
  result = dobContext.text;
  if (dobContext.changed && result !== dobContextBefore) piiFound.push('Date of birth');

  const dobBefore = result;
  result = redactDOB(result);
  if (result !== dobBefore) piiFound.push('Date of birth');

  const headerDateBefore = result;
  const headerDates = redactUnlabeledHeaderDates(result);
  result = headerDates.text;
  if (headerDates.changed && result !== headerDateBefore) piiFound.push('Date of birth');

  // 3. Age
  const ageBefore = result;
  result = redactAge(result);
  if (result !== ageBefore) piiFound.push('Age');

  const narrativeAgeBefore = result;
  const narrativeAge = redactNarrativeAge(result);
  result = narrativeAge.text;
  if (narrativeAge.changed && result !== narrativeAgeBefore) piiFound.push('Age');

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

  const insAmbigMatches = result.match(INSURANCE_ID_AMBIGUOUS);
  if (insAmbigMatches) piiFound.push('Insurance ID');
  result = result.replace(INSURANCE_ID_AMBIGUOUS, REDACTED);

  // 8b. Insurance IDs (pattern-only fallback, carrier-prefixed)
  const insPatMatches = result.match(INSURANCE_CARRIER);
  if (insPatMatches) piiFound.push('Insurance ID');
  result = result.replace(INSURANCE_CARRIER, REDACTED);

  // 9. Account numbers
  const acctMatches = result.match(ACCT);
  if (acctMatches) piiFound.push('Account #');
  result = result.replace(ACCT, REDACTED);

  // 9b. Unlabeled address-like lines before ID redaction changes their shape.
  const addrLineBefore = result;
  const addrLines = redactAddressLikeLines(result);
  result = addrLines.text;
  if (addrLines.changed && result !== addrLineBefore) piiFound.push('Patient address');

  // 9c. Unlabeled ID/account-like tokens. This intentionally errs on privacy.
  const idBefore = result;
  const ids = redactHighRiskIdentifiers(result);
  result = ids.text;
  if (ids.changed && result !== idBefore) piiFound.push('Identifier');

  // 10. Patient address (context-aware — keeps hospital addresses)
  const addrBefore = result;
  result = redactPatientAddress(result);
  if (result !== addrBefore) piiFound.push('Patient address');

  // 10b. Pattern-only US address fallback — catches unlabeled full addresses.
  const addrPatMatches = result.match(US_ADDRESS);
  if (addrPatMatches) piiFound.push('Patient address');
  const usAddress = redactUsAddresses(result);
  result = usAddress.text;

  // Final cleanup in case earlier passes partially transformed an email/ID.
  result = result.replace(EMAIL, REDACTED);
  result = result.replace(/\[REDACTED\]@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g, REDACTED);
  result = replaceAlnumIdentifiers(result);

  return { redacted: result, piiFound };
}
