// Remove build output and interpreter caches before a build that will be published, so
// nothing stale or opaque (an old dist/ file, a .pyc) can ride along in the tarball.
// SPDX-License-Identifier: Apache-2.0
import { rmSync } from 'node:fs';
for (const d of ['dist', 'conformance/__pycache__', 'test/__pycache__']) {
  rmSync(new URL(`../${d}`, import.meta.url), { recursive: true, force: true });
}
