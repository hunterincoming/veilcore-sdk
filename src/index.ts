// @veilcore/records — build, commit and verify VeilCore records.
//
// No chain dependency. Anyone can compute a record commitment with this package and
// nothing else, which is what makes the format adoptable by a registry we do not run.
//
// SPDX-License-Identifier: Apache-2.0

export * from './types.js';
export * from './canonical.js';
export * from './hash.js';
export * from './commit.js';
export * from './verify.js';
