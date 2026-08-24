#!/usr/bin/env node
// veilcore — check a record without writing any code.
//
// Everything else in this package assumes the reader writes JavaScript. An
// examiner, a seed control official or a certifying agency's analyst does not,
// and those are the people a record has to hold up in front of. This exposes
// the same operations as a command.
//
//     veilcore verify record.json          does the commitment hold, and what
//                                          do the attestations and anchors
//                                          actually establish
//     veilcore seal record.json            compute the commitment and write it
//     veilcore diff before.json after.json what changed, and is it material
//     veilcore canonical record.json       the exact bytes that get hashed
//     veilcore inclusion proof.json        does this proof fold to its root
//
// Exit status is 0 when the answer is yes, 1 when it is no, 2 when the command
// could not be run. That is what makes it usable in a script.
//
// SPDX-License-Identifier: Apache-2.0

import { readFile, writeFile } from 'node:fs/promises';
import {
  computeCommitment, verifyCommitment, canonicalise, newNonce,
  diffRecords, classifyCorrection,
  verifyAttestation, strengthOf,
  effectiveAnchors, standingOf, datingSummary,
  verifyInclusion,
  contestedStatus,
} from 'veilcore-records';

const OK = 0, NO = 1, ERR = 2;

const out = (s = '') => console.log(s);
const say = (k, v) => out(`  ${k.padEnd(22)} ${v}`);
const die = (msg) => { console.error(`veilcore: ${msg}`); process.exit(ERR); };

const load = async (path) => {
  if (!path) die('no file given');
  let text;
  try { text = await readFile(path, 'utf8'); }
  catch { die(`cannot read ${path}`); }
  try { return JSON.parse(text); }
  catch (e) { die(`${path} is not valid JSON: ${e.message}`); }
};

// ---------------------------------------------------------------------------

async function verify(path) {
  const rec = await load(path);
  let failed = false;

  out(`\n${rec.recordId ?? '(no recordId)'}`);
  out();

  // 1. the commitment
  const c = await verifyCommitment(rec);
  if (c.valid) {
    say('commitment', 'holds');
    say('', rec.commitment);
  } else {
    failed = true;
    say('commitment', 'DOES NOT HOLD');
    if (c.reason) say('reason', c.reason);
    if (c.computed) {
      say('recorded', rec.commitment ?? '(none)');
      say('computed', c.computed);
    }
    out();
    out('  The record does not match its own commitment. Either the record was');
    out('  changed after it was sealed, or the commitment was computed over');
    out('  something else. Nothing below can be relied on until this is resolved.');
  }
  out();

  // 2. what the attestations establish
  const atts = rec.attestations ?? [];
  if (atts.length === 0) {
    say('attestations', 'none');
    out();
    out('  Nobody outside the holder has vouched for this record. That is not a');
    out('  fault, but it means the contents rest on the holder\'s own assertion.');
  } else {
    say('attestations', String(atts.length));
    for (const a of atts) {
      const sig = await verifyAttestation(a).catch(() => false);
      if (!sig) failed = true;
      const strength = (() => { try { return strengthOf(a); } catch { return 'unknown'; } })();
      out();
      say('  attester', a.attester?.id ?? '(unnamed)');
      say('  signature', sig ? 'verifies' : 'DOES NOT VERIFY');
      say('  strength', strength);
      if (a.subjectCommitment && rec.commitment && a.subjectCommitment !== rec.commitment) {
        failed = true;
        say('  bound to', 'A DIFFERENT RECORD');
        out('    This attestation names a different commitment. A genuine');
        out('    signature over another record establishes nothing here.');
      }
    }
    out();
    out('  A signature proves the attestation was made by the holder of that key.');
    out('  Whether that key belongs to an accredited laboratory is a separate');
    out('  question, and no amount of cryptography answers it.');
  }
  out();

  // 3. what the anchors establish
  const anchors = effectiveAnchors(rec);
  if (anchors.length === 0) {
    say('anchors', 'none');
  } else {
    say('anchors', String(anchors.length));
    for (const a of anchors) say('  standing', standingOf(a));
  }
  say('dating', datingSummary(rec));
  out();

  // 4. challenges, if the record carries any
  const challenges = rec.challenges ?? [];
  if (challenges.length > 0) {
    const status = contestedStatus(challenges);
    say('contested', typeof status === 'string' ? status : JSON.stringify(status));
    out();
  }

  out(failed ? 'FAILED.' : 'Verified.');
  out();
  process.exit(failed ? NO : OK);
}

// ---------------------------------------------------------------------------

async function seal(path) {
  const rec = await load(path);

  if (rec.commitment) {
    const c = await verifyCommitment(rec);
    if (c.valid) {
      out(`\n  Already sealed, and the commitment holds.\n  ${rec.commitment}\n`);
      process.exit(OK);
    }
    die('this record already carries a commitment and it does not hold. '
      + 'Resealing would overwrite it and hide the discrepancy. Investigate first.');
  }

  // A nonce is what makes the commitment hiding as well as binding. Without it,
  // a guessable record can be confirmed by computing candidates.
  rec.profileData = rec.profileData ?? {};
  const added = !rec.profileData.nonce;
  if (added) rec.profileData.nonce = newNonce();

  rec.commitment = await computeCommitment(rec);
  const c = await verifyCommitment(rec);
  if (!c.valid) die('sealed but the result does not verify — this is a bug, please report it');

  await writeFile(path, JSON.stringify(rec, null, 2) + '\n');

  out(`\n  Sealed. ${path} rewritten.`);
  say('commitment', rec.commitment);
  if (added) {
    out();
    out('  A nonce was generated and added to profileData. KEEP IT. The commitment');
    out('  cannot be recomputed without it, and a record whose commitment cannot');
    out('  be recomputed cannot be verified by anyone, including you.');
  }
  out();
  process.exit(OK);
}

// ---------------------------------------------------------------------------

async function diff(a, b) {
  const before = await load(a), after = await load(b);
  const changes = diffRecords(before, after);

  out();
  if (changes.length === 0) {
    out('  No committed field changed.');
    out();
    process.exit(OK);
  }

  const sev = (s) => typeof s === 'string' ? s
    : `descent ${s.descent ?? '?'}, terms ${s.terms ?? '?'}`;

  for (const ch of changes) {
    say(ch.field, sev(ch.severity));
  }
  out();

  const overall = classifyCorrection(changes);
  say('overall', sev(overall));
  out();
  out('  Severity is a property of WHICH field changed, not of how large the');
  out('  change looks. An unclassified field defaults to material: an');
  out('  unrecognised change is not assumed harmless.');
  out();
  process.exit(OK);
}

// ---------------------------------------------------------------------------

async function canonical(path) {
  const rec = await load(path);
  // The exact bytes hashed. An implementer comparing against another
  // implementation needs to see this, not a description of it.
  process.stdout.write(canonicalise(rec) + '\n');
  process.exit(OK);
}

async function inclusion(path) {
  const proof = await load(path);
  const ok = await verifyInclusion(proof).catch((e) => { die(`not a usable proof: ${e.message}`); });
  out();
  say('commitment', proof.commitment ?? '(none)');
  say('root', proof.root ?? '(none)');
  say('path length', String(proof.path?.length ?? 0));
  say('result', ok ? 'folds to the stated root' : 'DOES NOT FOLD TO THE STATED ROOT');
  if (ok && !proof.anchor) {
    out();
    out('  The proof holds, but the batch root carries no anchor. The record is');
    out('  in a sealed batch whose root has not been published, so the proof');
    out('  establishes membership and not a date.');
  }
  out();
  process.exit(ok ? OK : NO);
}

// ---------------------------------------------------------------------------

const usage = () => {
  out(`
veilcore — check a VeilCore record without writing any code

  veilcore verify <record.json>            the commitment, the attestations,
                                           the anchors, and what each one
                                           does and does not establish
  veilcore seal <record.json>              compute the commitment and write it
                                           back into the file
  veilcore diff <before.json> <after.json> which committed fields changed and
                                           whether the correction is material
  veilcore canonical <record.json>         the exact serialisation that gets
                                           hashed, for comparing against
                                           another implementation
  veilcore inclusion <proof.json>          does this inclusion proof fold to
                                           its stated root

Exit status is 0 when the answer is yes, 1 when it is no, 2 when the command
could not be run.

Verification needs nothing but this package. No account, no network, no ledger.
`);
  process.exit(ERR);
};

const [cmd, ...args] = process.argv.slice(2);
switch (cmd) {
  case 'verify':    await verify(args[0]); break;
  case 'seal':      await seal(args[0]); break;
  case 'diff':      await diff(args[0], args[1]); break;
  case 'canonical': await canonical(args[0]); break;
  case 'inclusion': await inclusion(args[0]); break;
  case '--help': case '-h': case 'help': case undefined: usage(); break;
  default: die(`unknown command "${cmd}" — try veilcore --help`);
}
