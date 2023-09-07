import { run, mark, utils } from 'micro-bmark';
import { hash_to_field } from '../abstract/hash-to-curve.js';
import { hashToPrivateScalar } from '../abstract/modular.js';
import { randomBytes } from '@openpgp/noble-hashes/utils';
import { sha256 } from '@openpgp/noble-hashes/sha256';
// import { generateData } from './_shared.js';
import { hashToCurve as secp256k1 } from '../secp256k1.js';
import { hashToCurve as p256 } from '../p256.js';
import { hashToCurve as p384 } from '../p384.js';
import { hashToCurve as p521 } from '../p521.js';
import { hashToCurve as ed25519 } from '../ed25519.js';
import { hashToCurve as ed448 } from '../ed448.js';
import { utf8ToBytes } from '../abstract/utils.js';

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
run(async () => {
  const rand = randomBytes(40);
  await mark('hashToPrivateScalar', 1000000, () => hashToPrivateScalar(rand, N));
  // - p, the characteristic of F
  // - m, the extension degree of F, m >= 1
  // - L = ceil((ceil(log2(p)) + k) / 8), where k is the security of suite (e.g. 128)
  await mark('hash_to_field', 1000000, () =>
    hash_to_field(rand, 1, { DST: 'secp256k1', hash: sha256, expand: 'xmd', p: N, m: 1, k: 128 })
  );
  const msg = utf8ToBytes('message');
  for (let [title, fn] of Object.entries({ secp256k1, p256, p384, p521, ed25519, ed448 })) {
    await mark(`hashToCurve ${title}`, 1000, () => fn(msg));
  }
});
