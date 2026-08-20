# Profiles

The envelope carries what every subject has, whatever domain it comes from: a name, an
originator, a claimed creation date, identification evidence, declared descent, and any
external registrations. A profile carries what is specific to a domain, and nothing else.

That split is deliberate and it is not ours. UPOV has run this shape since 1961: the
conditions for a breeder's right — novelty, distinctness, uniformity, stability, a
denomination — apply to every species and live in the convention. What varies by species
lives in a Test Guideline. We have the same problem and the same answer.

## Published here

**`plant-variety-v1.json`** — what is specific to plants. Propagation type, breeding
method, sport origin, maturity group. Six fields, because everything else a plant breeder
records is either universal or crop-specific.

**`cannabis-v0.1.json`** — plant varieties plus phenotype selection and chemotype. Two
extra fields, published as a demonstration that a domain can extend without permission
and without anything upstream changing.

**`seed-lot-v1.json`** — a lot, not a variety. The seed world certifies per lot: ISTA
issues one certificate per lot, the OECD schemes label per lot, and a certifying agency's
determination attaches to a lot rather than to the variety it belongs to. Extends nothing,
because a lot is not a kind of variety; the link to the variety is a parent. Generation
classes — breeder, foundation, registered, certified — are a descent chain of lots rather
than four independent grades, so declared descent already carries them.

## Why they are small

A profile a body has to accept wholesale is a profile they have to negotiate. A profile of
six fields is one they can read in a minute and extend in an afternoon.

The test for whether a field belongs in the envelope rather than a profile: would an
ornamental propagator, a livestock herd book, and a microbial culture collection all need
it? Marker data passes — every domain identifies subjects by something measurable, and
the envelope carries the structure while the profile says what the values mean.
Propagation type fails. Seed versus vegetative means nothing to a herd book.

## Defining your own

**Nobody grants permission.** A profile is identified by an authority and a name, resolved
the same way a record is:

    veilcore/profile/plant-variety/v1     published by the authors of the specification
    example.org/profile/variety/v1        published by whoever controls example.org

Publish a JSON schema at a path you control and name it in your records. There is no
registry of profiles, because a registry of profiles is a body that can refuse one.

## The `x-veilcore` block

**`extends`** — the profile this builds on, where it builds on one. Advisory: a record
names one profile, and an implementation either recognises it or does not.

**`parentRoles`** — the vocabulary for declared descent in your domain.

**`provableFields`** — where a domain expects claims to be proven about single fields
rather than the whole record, the fields to commit and in what order. Numeric values are
scaled to integers because a proof system compares integers and 98.5 is not one; a scale
of 10 means tenths, so 98.5 commits as 985. The order is the order of the content tree,
and changing it produces a different schema.

**`correctionSeverity`** — for each field, whether a correction is material for descent
and for terms. See §6.2 of the specification. You may classify your own fields and may not
reclassify an envelope field: you know what a name change means in your domain, but nobody
may decide that changing a record's parents is cosmetic.

Anything unclassified defaults to material for both. An unrecognised change is not assumed
harmless.
