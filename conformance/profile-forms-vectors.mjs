// Vectors for two rules the record profiles share (SPEC 11.8, used by 11.9 and 11.11):
// what a `recordId` naming a logged record looks like, and what counts as white space at
// either end of one-line text. Written to profile-forms-v1.json, next to this file.
//
// The profile vector files (animal-individual-v1.json, strain-v1.json, document-v1.json) are
// byte-for-byte copies from the VeilCore web application, so these live in a file of their own
// rather than being added to those. Each case starts from one of those files' records and
// changes one value. Whether a case stands or is refused is written here by hand, from the
// specification; a case that stands carries its fingerprint, computed with this package's
// generic record fingerprint (section 3.6.1), never with any profile's own checks.
//
//   node conformance/profile-forms-vectors.mjs   (after npm run build), then npm run conformance:generate
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from 'node:fs';
import { canonicalise, computeRecordFingerprint } from '../dist/index.js';

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const clone = (o) => JSON.parse(JSON.stringify(o));
// The records each case starts from: one with a parent or an `about` entry naming a logged record.
const bases = {
  animal: read('./animal-individual-v1.json').records[3].fields,
  strain: read('./strain-v1.json').records[3].fields,
  document: read('./document-v1.json').records[0].fields,
};
const withRecordId = (profile, id) => {
  const f = clone(bases[profile]);
  (profile === 'document' ? f.about : f.parents)[0].recordId = id;
  return f;
};
const withLine = (profile, value) => {
  const f = clone(bases[profile]);
  f[profile === 'document' ? 'title' : 'name'] = value;
  return f;
};

const ID_128 = 'V' + 'a1'.repeat(63) + 'z';
const cases = [
  // ---- recordId: an ASCII letter or digit, then up to 127 ASCII letters, digits, . _ : - ----
  ['document', 'a record id of one letter', withRecordId('document', 'a'), true],
  ['document', 'a record id of one digit', withRecordId('document', '7'), true],
  ['document', 'a record id using every allowed mark (. _ : -)', withRecordId('document', 'vc_rec.2026:07-a'), true],
  ['document', 'a record id of 128 characters, the most', withRecordId('document', ID_128), true],
  ['document', 'a record id of 129 characters', withRecordId('document', ID_128 + '0'), false],
  ['document', 'an empty record id', withRecordId('document', ''), false],
  ['document', 'a record id starting with -', withRecordId('document', '-VEIL-0007'), false],
  ['document', 'a record id starting with .', withRecordId('document', '.VEIL'), false],
  ['document', 'a record id starting with _', withRecordId('document', '_VEIL'), false],
  ['document', 'a record id with a space inside', withRecordId('document', 'VEIL 0007'), false],
  ['document', 'a record id with a slash', withRecordId('document', 'VEIL/0007'), false],
  ['document', 'a record id ending in a line break', withRecordId('document', 'VEIL-0007\n'), false],
  ['document', 'a record id with a letter outside ASCII (É)', withRecordId('document', 'VÉIL-0007'), false],
  ['document', 'a record id with a full-width digit', withRecordId('document', 'VEIL-７'), false],
  ['document', 'a record id written as a number', withRecordId('document', 7), false],
  ['animal', 'an animal parent with a record id using every allowed mark', withRecordId('animal', 'vc_rec.2026:07-a'), true],
  ['animal', 'an animal parent with a record id starting with -', withRecordId('animal', '-VEIL-0017'), false],
  ['animal', 'an animal parent with a record id of 129 characters', withRecordId('animal', ID_128 + '0'), false],
  ['strain', 'a parent strain with a record id using every allowed mark', withRecordId('strain', 'vc_rec.2026:07-a'), true],
  ['strain', 'a parent strain with a record id with a space inside', withRecordId('strain', 'VEIL 0021'), false],
  ['strain', 'a parent strain with a record id with a letter outside ASCII', withRecordId('strain', 'VÉIL-0021'), false],

  // ---- white space at either end: exactly what ECMAScript's String.prototype.trim() removes ----
  ['document', 'a title ending in a no-break space (U+00A0)', withLine('document', 'Certificate of analysis '), false],
  ['document', 'a title starting with an ideographic space (U+3000)', withLine('document', '　Certificate of analysis'), false],
  ['document', 'a title ending in a byte order mark (U+FEFF)', withLine('document', 'Certificate of analysis﻿'), false],
  ['document', 'a title starting with a byte order mark (U+FEFF)', withLine('document', '﻿Certificate of analysis'), false],
  ['document', 'a title ending in a line separator (U+2028)', withLine('document', 'Certificate of analysis '), false],
  ['document', 'a title ending in a paragraph separator (U+2029)', withLine('document', 'Certificate of analysis '), false],
  ['document', 'a title ending in an ogham space mark (U+1680)', withLine('document', 'Certificate of analysis '), false],
  ['document', 'a title ending in a hair space (U+200A)', withLine('document', 'Certificate of analysis '), false],
  ['document', 'a title ending in a narrow no-break space (U+202F)', withLine('document', 'Certificate of analysis '), false],
  ['document', 'a title ending in a medium mathematical space (U+205F)', withLine('document', 'Certificate of analysis '), false],
  ['document', 'a title with a no-break space inside', withLine('document', 'Certificate of analysis'), true],
  ['document', 'a title with a byte order mark inside (only the ends are checked)', withLine('document', 'Certificate﻿of analysis'), true],
  ['document', 'a title ending in a zero-width space (U+200B is not white space)', withLine('document', 'Certificate of analysis​'), true],
  ['document', 'a title ending in a Mongolian vowel separator (U+180E is not white space)', withLine('document', 'Certificate of analysis᠎'), true],
  ['animal', 'an animal name ending in a byte order mark (U+FEFF)', withLine('animal', 'Practice Cow Two﻿'), false],
  ['animal', 'an animal name starting with an ideographic space (U+3000)', withLine('animal', '　Practice Cow Two'), false],
  ['animal', 'an animal name ending in a zero-width space (not white space)', withLine('animal', 'Practice Cow Two​'), true],
  ['strain', 'a strain name ending in a byte order mark (U+FEFF)', withLine('strain', 'Practice Line﻿'), false],
  ['strain', 'a strain name ending in a no-break space (U+00A0)', withLine('strain', 'Practice Line '), false],
  ['strain', 'a strain name with a no-break space inside', withLine('strain', 'Practice Line'), true],
];

const profileForms = [];
for (const [profile, name, fields, stands] of cases) {
  if (!stands) {
    profileForms.push({ name, profile, fields, refused: true });
    continue;
  }
  const r = await computeRecordFingerprint(fields);
  profileForms.push({ name, profile, fields, refused: false, canonical: canonicalise(fields), algorithm: r.algorithm, contentHash: r.contentHash, fingerprint: r.fingerprint });
}

writeFileSync(
  new URL('./profile-forms-v1.json', import.meta.url),
  JSON.stringify({ spec: 'SPEC 11.8 (record ids and white space), as used by 11.9 and 11.11', profileForms }, null, 2) + '\n',
);
const by = (p) => profileForms.filter((v) => v.profile === p).length;
console.log(`profile-forms-v1.json: ${profileForms.length} vectors (document ${by('document')}, animal ${by('animal')}, strain ${by('strain')}); ${profileForms.filter((v) => !v.refused).length} stand`);
