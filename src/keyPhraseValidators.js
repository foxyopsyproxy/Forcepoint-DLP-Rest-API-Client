// Named validators a pattern-based Key Phrase can reference from config (see
// keyPhraseConfig.js), keyed by name rather than accepting a function/code from the
// config file itself - config is data, never code, so a validator is always one of
// these known, reviewed functions and nothing else.
//
// A validator exists for cases a regex alone cannot express precisely: a national ID
// format is a fixed digit count, but not every number of that length is a real id -
// most schemes add a checksum digit specifically so typos and random numbers can be
// told apart from genuine ones. Matching the digit count with a regex and then
// checking the checksum here keeps the common case (a real id) redacted while
// leaving unrelated numbers (invoice numbers, phone extensions, ...) alone.

// Israeli ID numbers ("Teudat Zehut"): 9 digits (shorter numbers are conventionally
// left-padded with zeros), validated with a Luhn-style weighted checksum - each
// digit is multiplied by 1 or 2 alternating from the left, any two-digit product has
// its own digits summed (equivalent to subtracting 9), and the total must be a
// multiple of 10. Public, widely-documented algorithm - not Forcepoint-proprietary.
function israeliId(candidate) {
  const digits = String(candidate).replace(/\D/g, '');
  if (digits.length < 5 || digits.length > 9) return false;
  const padded = digits.padStart(9, '0');
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    let product = Number(padded[i]) * ((i % 2) + 1);
    if (product > 9) product -= 9;
    sum += product;
  }
  return sum % 10 === 0;
}

const VALIDATORS = { israeliId };

module.exports = { VALIDATORS };
