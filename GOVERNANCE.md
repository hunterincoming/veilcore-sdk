# How the format changes

The record format in [SPEC.md](SPEC.md) is a draft, version 0.1, published for comment. This
file says how it changes, who decides, and what has to be true before it is called 1.0.

The short version: a record that verifies today keeps verifying. Anything that would change
what a record commits to is a new format version, decided in public, with test vectors and two
implementations before it ships.

## The promise

**A record that verified keeps verifying.** For a released `formatVersion`, these never change:
the list of committed fields (section 4.2), canonical serialization (section 4.4) and the
commitment algorithm. Changing any of them makes a new `formatVersion`. Verifiers keep reading
the old one; nothing already sealed is reinterpreted.

**A profile's committed fields don't change under its identifier** once the profile is final.
A change is a new profile version (section 11.6). Draft profiles (sections 11.8 and 11.9) say
so at the top, and may still change until they say they are final.

**Nothing depends on fetching anything from us.** A commitment is computed from the record
itself, so no change here, and no change to a published profile, can alter a record already
sealed.

## Kinds of change

| Kind | Examples | How |
|---|---|---|
| Editorial | Clearer wording, a new example, a typo | Any time. Noted in the revision line at the top of SPEC.md. |
| Additive | A new vector, a new anchor kind, a new optional field outside the committed set, a new profile | A minor release. Old records and old verifiers are unaffected. Vectors land with the change. |
| Breaking | Anything that changes a record's commitment, or makes a valid record invalid | A new `formatVersion`, through the steps below. |

A breaking change goes through, in order:

1. An issue on this repository that states the problem before any solution.
2. At least 30 days open for comment, announced in the README.
3. Test vectors for the new behavior, including what an implementation must refuse.
4. Two implementations passing them.
5. A release that reads both the old and the new version.

## Proposing a change

Open an issue on this repository. Say what goes wrong and show a record or input that shows it.
[Issue #1](https://github.com/hunterincoming/veilcore-sdk/issues/1) is the model: an
implementer built the format from the document alone, found four places where two readings were
possible, and each became a rule with a test.

Security problems go privately, as [SECURITY.md](SECURITY.md) says.

## Who decides

Today, the authors of the specification (VeilCore's founders) decide, on the issue, in public,
with the reason written down. Every change to the format is listed in
[CHANGELOG.md](CHANGELOG.md), from 0.16.0 on; earlier ones are in the commit history.

The comments that carry most weight are from people who have implemented the format and pass
the vectors, because they find what a reader of the text alone can't.

The format is Apache-2.0. Anyone may implement it, extend it with their own profiles, or fork
it, without asking. The aim is to hand stewardship to a standards body or an independent group
once one will take it on. Until then, this file is the rule we hold ourselves to.

## What 1.0 needs

1.0 is a set of conditions, not a date:

1. **An implementation by someone unrelated to the authors** passes the conformance vectors.
   The three implementations today share an author, which shows the vectors hold across
   languages, not that the document is enough on its own.
2. **Vectors for corrections and resolution** (sections 6 and 11.5), which today are implemented
   in the reference implementation but not yet in the vector set.
3. **An outside review** of the specification and the reference implementation.
4. **Real records from at least one breeder or lab outside the team**, so the format has met
   real data.
5. **A 1.0 release candidate open for comment for 30 days.**

The draft sections (11.8 animal records, 11.9 strain records, 11.10 deal records) are not part
of 1.0 unless they are final by then. They keep their own versions.

After 1.0, the promise above holds without exception for `formatVersion` 1.
