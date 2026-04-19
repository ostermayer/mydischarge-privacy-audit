// Synthetic discharge-document templates in the app's 15 supported languages.
// Each template uses PHI/provider placeholders. The generator substitutes values
// from phi_pool.js. Templates include labels that redact.js is designed to match
// (e.g., "Patient Name:", "DOB:", etc.) so the redactor's label-based rules fire.

export const LANGUAGES = [
  'EN', 'ES', 'ZH', 'VI', 'KO', 'TL', 'AR', 'FR', 'RU',
  'PT', 'HT', 'DE', 'JA', 'HI', 'FA',
];

// label / value substitution is done with %PLACEHOLDERS%.
// PHI placeholders:  %NAME% %DOB% %AGE% %SSN% %PHONE% %EMAIL% %MRN% %INS% %ACCT% %ADDR%
// Provider:          %HOSP% %HOSPPHONE% %DOC% %DRUG% %DX% %APPT%

export const TEMPLATES = {
  EN: [
    `EMERGENCY DEPARTMENT DISCHARGE INSTRUCTIONS
%HOSP%
Hospital Phone: %HOSPPHONE%

Patient Name: %NAME%
DOB: %DOB%    Age: %AGE%
SSN: %SSN%
Patient Phone: %PHONE%
Patient Email: %EMAIL%
Patient Address: %ADDR%
MRN: %MRN%
Insurance ID: %INS%
Account #: %ACCT%

Attending: %DOC%
Diagnosis: %DX%
Medication: Take %DRUG% as directed until finished.
Follow-up: Please schedule a follow-up appointment on %APPT% with your primary care provider.
If you develop chest pain, shortness of breath, or fever above 101°F, call 911 or return to the ED immediately.`,

    `DISCHARGE SUMMARY
Facility: %HOSP% (call %HOSPPHONE% for questions)
Name: %NAME%
Date of Birth: %DOB%
Age: %AGE% years
Home Address: %ADDR%
Cell: %PHONE%
Email: %EMAIL%
Medical Record Number: %MRN%
Member ID: %INS%
Primary provider: %DOC%
Diagnosis: %DX%
Your doctor prescribed %DRUG%.
Follow up on %APPT%.`,
  ],

  ES: [
    `INSTRUCCIONES DE ALTA - DEPARTAMENTO DE EMERGENCIAS
%HOSP%
Teléfono del Hospital: %HOSPPHONE%

Nombre del Paciente: %NAME%
Fecha de Nacimiento: %DOB%    Edad: %AGE%
Número de Seguro Social: %SSN%
Celular del paciente: %PHONE%
Correo del paciente: %EMAIL%
Dirección del Paciente: %ADDR%
Número de Expediente: %MRN%
Número de Seguro: %INS%
Cuenta: %ACCT%

Médico: %DOC%
Diagnóstico: %DX%
Medicamento: Tome %DRUG% según indicación.
Seguimiento: Cita el %APPT% con su proveedor.
Si tiene dolor de pecho o fiebre, llame al 911.`,
  ],

  ZH: [
    `急诊科出院说明
医院: %HOSP%
医院电话: %HOSPPHONE%

患者姓名: %NAME%
出生日期: %DOB%   年龄: %AGE%
社会安全号: %SSN%
患者手机: %PHONE%
患者邮箱: %EMAIL%
患者地址: %ADDR%
病历号: %MRN%
保险号: %INS%
账号: %ACCT%

主治医师: %DOC%
诊断: %DX%
药物: 按医嘱服用 %DRUG%。
复诊: 请于 %APPT% 随访您的医生。
如出现胸痛、呼吸困难或发热,请立即拨打 911。`,
  ],

  VI: [
    `HƯỚNG DẪN XUẤT VIỆN - KHOA CẤP CỨU
Bệnh viện: %HOSP%
Điện thoại bệnh viện: %HOSPPHONE%

Tên bệnh nhân: %NAME%
Ngày sinh: %DOB%   Tuổi: %AGE%
Số an sinh xã hội: %SSN%
Di động bệnh nhân: %PHONE%
Email bệnh nhân: %EMAIL%
Địa chỉ bệnh nhân: %ADDR%
Mã bệnh nhân: %MRN%
Số thẻ bảo hiểm: %INS%

Bác sĩ: %DOC%
Chẩn đoán: %DX%
Thuốc: Uống %DRUG% theo chỉ dẫn.
Tái khám: Lịch hẹn %APPT% với bác sĩ của bạn.`,
  ],

  KO: [
    `응급실 퇴원 안내
병원: %HOSP%
병원 전화: %HOSPPHONE%

환자명: %NAME%
생년월일: %DOB%   나이: %AGE%
주민번호: %SSN%
환자 휴대폰: %PHONE%
환자 이메일: %EMAIL%
환자 주소: %ADDR%
등록번호: %MRN%
보험번호: %INS%

담당의: %DOC%
진단: %DX%
약물: %DRUG% 처방대로 복용하세요.
진료 예약: %APPT%에 의사 선생님과 진료 예약이 있습니다.`,
  ],

  TL: [
    `MGA TAGUBILIN SA PAGLABAS - ER
Ospital: %HOSP%
Telepono ng ospital: %HOSPPHONE%

Pangalan ng pasyente: %NAME%
Petsa ng Kapanganakan: %DOB%   Edad: %AGE%
SSN: %SSN%
Telepono ng pasyente: %PHONE%
Email: %EMAIL%
Tirahan: %ADDR%
MRN: %MRN%
Insurance ID: %INS%

Doktor: %DOC%
Diagnosis: %DX%
Gamot: Inumin ang %DRUG% ayon sa reseta.
Follow-up: %APPT% kasama ang inyong doktor.`,
  ],

  AR: [
    `تعليمات الخروج من قسم الطوارئ
المستشفى: %HOSP%
هاتف المستشفى: %HOSPPHONE%

اسم المريض: %NAME%
تاريخ الميلاد: %DOB%    العمر: %AGE%
رقم الضمان الاجتماعي: %SSN%
جوال المريض: %PHONE%
البريد الإلكتروني للمريض: %EMAIL%
عنوان المريض: %ADDR%
رقم الملف الطبي: %MRN%
رقم التأمين: %INS%

الطبيب: %DOC%
التشخيص: %DX%
الدواء: خذ %DRUG% حسب التعليمات.
المتابعة: موعد %APPT% مع طبيبك.`,
  ],

  FR: [
    `INSTRUCTIONS DE SORTIE - URGENCES
Hôpital: %HOSP%
Téléphone de l'hôpital: %HOSPPHONE%

Nom du Patient: %NAME%
Date de Naissance: %DOB%   Âge: %AGE%
Numéro de Sécurité Sociale: %SSN%
Portable patient: %PHONE%
Email patient: %EMAIL%
Adresse du Patient: %ADDR%
Numéro de Dossier: %MRN%
Numéro d'Assurance: %INS%

Médecin: %DOC%
Diagnostic: %DX%
Médicament: Prenez %DRUG% selon prescription.
Rendez-vous: %APPT% avec votre médecin.`,
  ],

  RU: [
    `ИНСТРУКЦИИ ПРИ ВЫПИСКЕ - ОТДЕЛЕНИЕ НЕОТЛОЖНОЙ ПОМОЩИ
Больница: %HOSP%
Телефон больницы: %HOSPPHONE%

ФИО пациента: %NAME%
Дата рождения: %DOB%   Возраст: %AGE%
СНИЛС: %SSN%
Мобильный пациента: %PHONE%
Email пациента: %EMAIL%
Адрес пациента: %ADDR%
Номер карты: %MRN%
Номер страховки: %INS%

Врач: %DOC%
Диагноз: %DX%
Лекарство: Принимайте %DRUG% по назначению.
Запись на приём: %APPT% к вашему врачу.`,
  ],

  PT: [
    `INSTRUÇÕES DE ALTA - EMERGÊNCIA
Hospital: %HOSP%
Telefone do hospital: %HOSPPHONE%

Nome do Paciente: %NAME%
Data de Nascimento: %DOB%   Idade: %AGE%
CPF: %SSN%
Celular do paciente: %PHONE%
Email do paciente: %EMAIL%
Endereço do Paciente: %ADDR%
Número do Prontuário: %MRN%
Número do Seguro: %INS%

Médico: %DOC%
Diagnóstico: %DX%
Medicamento: Tome %DRUG% conforme prescrito.
Retorno: Consulta em %APPT% com seu médico.`,
  ],

  HT: [
    `ENSTRIKSYON SÒTI - IJANS
Lopital: %HOSP%
Telefòn lopital: %HOSPPHONE%

Non pasyan: %NAME%
Dat Nesans: %DOB%   Laj: %AGE%
SSN: %SSN%
Telefòn pasyan: %PHONE%
Email pasyan: %EMAIL%
Adrès Pasyan: %ADDR%
Nimewo Dosye: %MRN%
Nimewo Asirans: %INS%

Doktè: %DOC%
Dyagnostik: %DX%
Medikaman: Pran %DRUG% jan yo preskri a.
Swivi: Randevou %APPT% ak doktè ou.`,
  ],

  DE: [
    `ENTLASSUNGSHINWEISE - NOTAUFNAHME
Krankenhaus: %HOSP%
Telefon Krankenhaus: %HOSPPHONE%

Patientenname: %NAME%
Geburtsdatum: %DOB%   Alter: %AGE%
Sozialversicherungsnummer: %SSN%
Handy Patient: %PHONE%
Email Patient: %EMAIL%
Patientenadresse: %ADDR%
Patientennummer: %MRN%
Versicherungsnummer: %INS%

Arzt: %DOC%
Diagnose: %DX%
Medikament: Nehmen Sie %DRUG% wie verordnet.
Termin: %APPT% bei Ihrem Arzt.`,
  ],

  JA: [
    `救急科退院指示
病院: %HOSP%
病院電話: %HOSPPHONE%

患者氏名: %NAME%
生年月日: %DOB%   年齢: %AGE%
社会保障番号: %SSN%
患者携帯: %PHONE%
患者メール: %EMAIL%
患者住所: %ADDR%
患者番号: %MRN%
保険証番号: %INS%

担当医: %DOC%
診断: %DX%
薬: 処方通り %DRUG% を服用してください。
受診予約: %APPT% に主治医を受診してください。`,
  ],

  HI: [
    `आपातकालीन विभाग से छुट्टी के निर्देश
अस्पताल: %HOSP%
अस्पताल फोन: %HOSPPHONE%

रोगी का नाम: %NAME%
जन्म तिथि: %DOB%   आयु: %AGE%
सामाजिक सुरक्षा संख्या: %SSN%
रोगी मोबाइल: %PHONE%
रोगी ईमेल: %EMAIL%
रोगी का पता: %ADDR%
रोगी संख्या: %MRN%
बीमा संख्या: %INS%

डॉक्टर: %DOC%
निदान: %DX%
दवा: %DRUG% निर्देशानुसार लें।
अनुवर्ती: %APPT% को अपने डॉक्टर के पास जाएँ।`,
  ],

  FA: [
    `دستورالعمل ترخیص - اورژانس
بیمارستان: %HOSP%
تلفن بیمارستان: %HOSPPHONE%

نام بیمار: %NAME%
تاریخ تولد: %DOB%   سن: %AGE%
شماره تأمین اجتماعی: %SSN%
موبایل بیمار: %PHONE%
ایمیل بیمار: %EMAIL%
آدرس بیمار: %ADDR%
شماره پرونده: %MRN%
شماره بیمه: %INS%

پزشک: %DOC%
تشخیص: %DX%
دارو: %DRUG% را طبق دستور مصرف کنید.
پیگیری: نوبت %APPT% با پزشک خود.`,
  ],
};
