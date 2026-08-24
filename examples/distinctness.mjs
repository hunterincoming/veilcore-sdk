// Establishing that two varieties are distinct, without disclosing either panel.
//
// A breeder applying for plant variety protection has to show the variety is
// distinct from everything already known. Morphology often cannot show it -
// yield varies too much between seasons and sites to describe a variety by - so
// breeders increasingly rely on molecular markers. Those markers are the output
// of years of work and are treated as a trade secret.
//
// That leaves an examiner in a position nobody chose. He needs to see the marker
// data to make a determination. The breeder will not expose it. And the office
// does not want to be responsible for keeping someone's trade secrets safe: it
// prevents release of material it is not authorised to publish, but less risk is
// better than more.
//
// This example shows what a breeder seals, what an examiner receives, and where
// the disclosure actually sits. It runs with nothing but this package - no
// account, no network, no ledger:
//
//     npm install veilcore-records
//     node distinctness.mjs
//
// SPDX-License-Identifier: Apache-2.0

import {
  computeCommitment, verifyCommitment,
  generateKeypair, signAttestation, verifyAttestation,
  newNonce,
} from 'veilcore-records';

const line = (s) => console.log(`\n== ${s} ==`);
const say = (k, v) => console.log(`   ${k.padEnd(26)} ${v}`);

// A ten-locus SSR panel. The values are allele-size pairs, which is what an
// SSR panel produces. These two varieties share six loci and differ at four -
// enough shared ancestry to make distinctness a real question, enough
// difference to establish it.
const PANEL_A = {
  locus01: '192/198', locus02: '145/151', locus03: '233/233', locus04: '170/178',
  locus05: '201/207', locus06: '156/162', locus07: '244/250', locus08: '183/183',
  locus09: '129/135', locus10: '218/224',
};
const PANEL_B = {
  locus01: '192/198', locus02: '147/151', locus03: '233/233', locus04: '170/178',
  locus05: '201/213', locus06: '156/162', locus07: '244/250', locus08: '183/189',
  locus09: '129/135', locus10: '224/230',
};

// The panel is a named method and the values it produced. A method without its
// values proves nothing, and values without their method are not a statement,
// so they travel together.
const variety = (id, name, panel, created) => ({
  formatVersion: '0.1',
  recordId: `vc:northfield.example.com/${id}`,
  subjectType: 'plant-variety',
  profile: 'veilcore/profile/plant-variety/v1',
  commitment: '',
  commitmentAlgorithm: 'sha256/canonical-json/v1',
  anchor: { chain: 'midnight', network: 'undeployed' },
  sealedAt: '2026-08-23T12:00:00Z',
  holder: { id: 'vc:northfield.example.com/holder' },
  parents: [],
  attestations: [],
  subject: {
    name,
    internalDesignation: id,
    originator: 'Northfield Breeding Programme',
    claimedCreationDate: created,
  },
  identification: {
    method: 'SSR',
    panel: 'demo-ssr-10/v1',
    data: panel,
    performedBy: 'Example Analytics Ltd',
    performedOn: '2026-08-01',
  },
  profileData: {
    nonce: newNonce(),
    propagationType: 'seed',
    breedingMethod: 'cross',
  },
});

line('1. The breeder seals both varieties');

const a = variety('NF-0417', 'Northfield 0417', PANEL_A, '2024-03-11');
const b = variety('NF-0552', 'Northfield 0552', PANEL_B, '2025-06-02');
a.commitment = await computeCommitment(a);
b.commitment = await computeCommitment(b);

say('NF-0417', a.commitment.slice(0, 32) + '...');
say('NF-0552', b.commitment.slice(0, 32) + '...');
say('panels', 'held by the breeder, never published');
say('both verify', ((await verifyCommitment(a)).valid && (await verifyCommitment(b)).valid) ? 'yes' : 'no');

console.log(`
   Sealing is not registration and not a right. It fixes what the breeder held
   and when, so that a claim made later can be checked against it rather than
   asserted. The commitment is SHA-256 over a canonical serialisation, so any
   implementation in any language reproduces it, and the nonce makes it hiding
   as well as binding - without it, a guessable panel could be confirmed by
   computing candidates until one matched.`);

// ---------------------------------------------------------------------------

line('2. The laboratory signs for the panels it produced');

// The examiner is not being asked to trust the breeder about the breeder's own
// markers. Accuracy comes from a party with something to lose. The signature
// binds the statement to a key, and the key to an accredited laboratory is a
// separate question that no amount of cryptography answers.
const lab = await generateKeypair();

const attestationFor = (record, id) => signAttestation({
  attestationId: id,
  type: 'marker-panel',
  attester: {
    id: 'lab:example-analytics.example.com',
    name: 'Example Analytics Ltd',
    accreditation: 'ISO/IEC 17025',
    publicKey: lab.publicKey,
  },
  // Binds this attestation to THIS record. Without it a genuine signature could
  // be lifted onto a different record and would verify there.
  subjectCommitment: record.commitment,
  documentHash: 'f'.repeat(64),
  hashAlgorithm: 'sha256',
  issuedAt: '2026-08-02T09:00:00Z',
}, lab.privateKey);

a.attestations = [await attestationFor(a, 'att_panel_0417')];
b.attestations = [await attestationFor(b, 'att_panel_0552')];
a.commitment = await computeCommitment(a);
b.commitment = await computeCommitment(b);

say('attester', a.attestations[0].attester.id);
say('accreditation', a.attestations[0].attester.accreditation);
say('signatures verify', (await verifyAttestation(a.attestations[0]) && await verifyAttestation(b.attestations[0])) ? 'yes' : 'no');

console.log(`
   The panel report itself never enters the record. Only its hash. The
   laboratory keeps the report and produces it if a dispute ever requires it.`);

// ---------------------------------------------------------------------------

line('3. What an examiner is asked to accept today');

// The whole difficulty in one place. Today there are two options and an
// examiner has to pick one.
const differing = Object.keys(PANEL_A).filter((k) => PANEL_A[k] !== PANEL_B[k]);

console.log(`
   OPTION ONE - the breeder shows the panels.

   The examiner sees ${Object.keys(PANEL_A).length} loci for each variety, forms a view, and makes a
   determination he can defend. And from that moment the office holds a copy of
   a trade secret it did not want and must now protect for as long as it keeps
   the file.

   OPTION TWO - the breeder asserts distinctness and shows nothing.

   The office holds nothing, and has established nothing either. A determination
   resting on an applicant's own say-so is the thing an opponent attacks first.

   Neither option is anyone's preference. They are what is available.`);

// ---------------------------------------------------------------------------

line('4. What this format changes, and what it does not');

console.log(`
   What it changes now, with nothing but this package:

   The panels are SEALED. If the breeder later shows an examiner the markers,
   the examiner can confirm they are the same values that existed on the date
   they were sealed, and that nothing has moved since. A panel produced during a
   dispute can be checked against the record rather than taken on trust. And
   because the commitment is recomputable by anyone, that check does not depend
   on the breeder's software, this package, or the company that wrote it.

   What it does NOT change:

   An examiner who has been shown markers has seen them. Sealing does not undo
   that. What it changes is whether a copy has to persist anywhere after the
   determination is made - the breeder holds the data and can re-prove it to
   anyone, at any time, so there is no reason for the office to keep one.

   Whether that is worth anything is a question for the office, not for us.`);

// ---------------------------------------------------------------------------

line('5. The part that is not in this package');

console.log(`
   Establishing distinctness WITHOUT the examiner seeing either panel needs a
   per-field commitment scheme: each locus committed as a leaf under a sealed
   root, so a claim can be proven about the panel while every value stays
   closed. Section 12 of the specification describes that as not yet specified
   here, and states what specifying it would have to settle.

   An independent implementation of that shape exists and has been exercised
   against records in this format. It establishes that two sealed panels differ
   at k or more loci - a threshold the examiner sets - without disclosing a
   single value.

   Two properties of it are worth knowing before an office relies on one.

   IT DOES NOT REVEAL WHICH LOCI DIFFER, and that is deliberate rather than
   incidental. An examination compares an applicant against KNOWN reference
   varieties. If a proof showed which loci differ against a known reference,
   then "these two match here" leaks the applicant's value at that locus - and
   enough comparisons rebuild the whole profile without a single value ever
   being disclosed. The count is the claim; the positions are not.

   AND A CLAIM THE DATA DOES NOT SUPPORT CANNOT BE CONSTRUCTED. In this pair,
   ${differing.length} loci differ. A claim of "at least ${differing.length}" is provable. A claim of
   "at least ${differing.length + 4}" fails while it is being built, on the breeder's own machine,
   before anything is published. An applicant cannot assert a distinctness they
   do not have.

   Verification does not require us. The result is recorded in state a verifier
   reads directly, so an office confirms a determination years later without
   asking anyone - which is the same constraint as section 11: a record must
   survive its registry.`);

// ---------------------------------------------------------------------------

line('Summary');

console.log(`
   Held by the breeder:    both marker panels, and the trial data behind them
   Signed by the lab:      that the panels are theirs, bound to these records
   Sealed and checkable:   what was held, and when
   Held by the office:     a determination it can defend, and no trade secret

   The disclosure an examination requires is a policy question. What a format
   can do is make sure that whatever is disclosed can be checked, and that
   nothing else has to be.`);
