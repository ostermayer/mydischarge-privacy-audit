/**
 * Server-side input sanitization — strips prompt injection patterns
 * from user input before it reaches the LLM.
 */

const INJECTION_PATTERNS = [
  // Direct instruction overrides
  /ignore\s+(all\s+)?(previous|prior|above|earlier|system)\s+(instructions?|prompts?|rules?|directions?)/gi,
  /disregard\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|prompts?|rules?)/gi,
  /forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|prompts?|rules?)/gi,
  /override\s+(all\s+)?(previous|prior|system)\s+(instructions?|prompts?|rules?)/gi,
  // System prompt extraction
  /repeat\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/gi,
  /show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/gi,
  /what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules?)/gi,
  /output\s+(your|the)\s+(system\s+)?(prompt|instructions?)/gi,
  /print\s+(your|the)\s+(system\s+)?(prompt|instructions?)/gi,
  // Role hijacking
  /you\s+are\s+now\s+(a|an)\s+/gi,
  /act\s+as\s+(a|an)\s+(?!patient)/gi,  // allow "act as a patient"
  /pretend\s+(to\s+be|you\s+are)\s/gi,
  /switch\s+to\s+(\w+)\s+mode/gi,
  /enter\s+(\w+)\s+mode/gi,
  /new\s+instructions?:/gi,
  // DAN / jailbreak patterns
  /\bDAN\b.*\bmode\b/gi,
  /developer\s+mode/gi,
  /jailbreak/gi,
];

/**
 * Strips known prompt injection patterns from text.
 * Returns the cleaned text.
 */
function sanitize(text) {
  if (!text) return text;
  let result = text;
  for (const pattern of INJECTION_PATTERNS) {
    result = result.replace(pattern, '[removed]');
    pattern.lastIndex = 0;
  }
  return result;
}

module.exports = { sanitize };
