import { BigInteger } from '@openpgp/noble-hashes/biginteger';

import { deepStrictEqual, ok } from 'assert';
import { describe, should } from 'micro-should';
import { brainpoolP256r1 } from '../esm/brainpoolP256r1.js';
import { brainpoolP384r1 } from '../esm/brainpoolP384r1.js';
import { brainpoolP512r1 } from '../esm/brainpoolP512r1.js';
import { hexToBytes, bytesToHex } from '../esm/abstract/utils.js';
import { default as ecdsa } from './wycheproof/ecdsa_test.json' assert { type: 'json' };
import { default as ecdh } from './wycheproof/ecdh_test.json' assert { type: 'json' };
import { default as rfc7027 } from './vectors/rfc7027.json' assert { type: 'json' };

import { default as ecdh_brainpoolP256r1_test } from './wycheproof/ecdh_brainpoolP256r1_test.json' assert { type: 'json' };
import { default as ecdh_brainpoolP384r1_test } from './wycheproof/ecdh_brainpoolP384r1_test.json' assert { type: 'json' };
import { default as ecdh_brainpoolP512r1_test } from './wycheproof/ecdh_brainpoolP512r1_test.json' assert { type: 'json' };

import { default as brainpoolP256r1_sha256_test } from './wycheproof/ecdsa_brainpoolP256r1_sha256_test.json' assert { type: 'json' };
import { default as brainpoolP256r1_sha3_256_test } from './wycheproof/ecdsa_brainpoolP256r1_sha3_256_test.json' assert { type: 'json' };
import { default as brainpoolP384r1_sha384_test } from './wycheproof/ecdsa_brainpoolP384r1_sha384_test.json' assert { type: 'json' };
import { default as brainpoolP384r1_sha3_384_test } from './wycheproof/ecdsa_brainpoolP384r1_sha3_384_test.json' assert { type: 'json' };
import { default as brainpoolP512r1_sha512_test } from './wycheproof/ecdsa_brainpoolP512r1_sha512_test.json' assert { type: 'json' };
import { default as brainpoolP512r1_sha3_512_test } from './wycheproof/ecdsa_brainpoolP512r1_sha3_512_test.json' assert { type: 'json' };

import { sha3_256, sha3_384, sha3_512 } from '@openpgp/noble-hashes/sha3';
import { sha512, sha384 } from '@openpgp/noble-hashes/sha512';
import { sha256 } from '@openpgp/noble-hashes/sha256';

const hex = bytesToHex;
const equalBigInteger = (actual, expected, msg) => ok(actual.toString() === expected.toString(), msg);

// prettier-ignore
const BRAINPOOL = {
  brainpoolP256r1,
  brainpoolP384r1,
  brainpoolP512r1
};

describe('Brainpool curves', () => {});
should('fields', () => {
  const vectors = {
    brainpoolP256r1: BigInteger.new('0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377'),
    brainpoolP384r1: BigInteger.new('0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53'),
    brainpoolP512r1: BigInteger.new('0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3')
  };
  for (const n in vectors) deepStrictEqual(BRAINPOOL[n].CURVE.Fp.ORDER, vectors[n]);
});

describe('wycheproof ECDH', () => {
  for (const group of ecdh.testGroups) {
    const CURVE = BRAINPOOL[group.curve];
    if (!CURVE) continue;
    should(group.curve, () => {
      for (const test of group.tests) {
        if (test.result === 'valid' || test.result === 'acceptable') {
          try {
            const pub = CURVE.ProjectivePoint.fromHex(test.public);
          } catch (e) {
            // Our strict validation filter doesn't let weird-length DER vectors
            if (e.message.startsWith('Point of length')) continue;
            throw e;
          }
          const shared = CURVE.getSharedSecret(test.private, test.public);
          deepStrictEqual(shared, test.shared, 'valid');
        } else if (test.result === 'invalid') {
          let failed = false;
          try {
            CURVE.getSharedSecret(test.private, test.public);
          } catch (error) {
            failed = true;
          }
          deepStrictEqual(failed, true, 'invalid');
        } else throw new Error('unknown test result');
      }
    });
  }

  // More per curve tests
  const WYCHEPROOF_ECDH = {
    brainpoolP256r1: {
      curve: brainpoolP256r1,
      tests: [ecdh_brainpoolP256r1_test],
    },
    brainpoolP384r1: {
      curve: brainpoolP384r1,
      tests: [ecdh_brainpoolP384r1_test],
    },
    brainpoolP512r1: {
      curve: brainpoolP512r1,
      tests: [ecdh_brainpoolP512r1_test],
    },
  };

  for (const name in WYCHEPROOF_ECDH) {
    const { curve, tests } = WYCHEPROOF_ECDH[name];
    for (let i = 0; i < tests.length; i++) {
      const test = tests[i];
      for (let j = 0; j < test.testGroups.length; j++) {
        const group = test.testGroups[j];
        should(`additional ${name} (${i}/${j})`, () => {
          for (const test of group.tests) {
            if (test.result === 'valid' || test.result === 'acceptable') {
              try {
                const pub = curve.ProjectivePoint.fromHex(test.public);
              } catch (e) {
                // Our strict validation filter doesn't let weird-length DER vectors
                if (e.message.includes('Point of length')) continue;
                throw e;
              }
              const shared = curve.getSharedSecret(test.private, test.public);
              deepStrictEqual(hex(shared), test.shared, 'valid');
            } else if (test.result === 'invalid') {
              let failed = false;
              try {
                curve.getSharedSecret(test.private, test.public);
              } catch (error) {
                failed = true;
              }
              deepStrictEqual(failed, true, 'invalid');
            } else throw new Error('unknown test result');
          }
        });
      }
    }
  }
});

const WYCHEPROOF_ECDSA = {
  brainpoolP256r1: {
    curve: brainpoolP256r1,
    hashes: {
      sha256: {
        hash: sha256,
        tests: [brainpoolP256r1_sha256_test],
      },
      sha3_256: {
        hash: sha3_256,
        tests: [brainpoolP256r1_sha3_256_test],
      },
    },
  },
  brainpoolP384r1: {
    curve: brainpoolP384r1,
    hashes: {
      sha384: {
        hash: sha384,
        tests: [brainpoolP384r1_sha384_test],
      },
      sha3_384: {
        hash: sha3_384,
        tests: [brainpoolP384r1_sha3_384_test],
      },
    },
  },
  brainpoolP512r1: {
    curve: brainpoolP512r1,
    hashes: {
      sha384: {
        hash: sha512,
        tests: [brainpoolP512r1_sha512_test],
      },
      sha3_512: {
        hash: sha3_512,
        tests: [brainpoolP512r1_sha3_512_test],
      },
    },
  },
};

function runWycheproof(name, CURVE, group, index) {
  const key = group.publicKey;
  const pubKey = CURVE.ProjectivePoint.fromHex(key.uncompressed);
  equalBigInteger(pubKey.x, BigInt(`0x${key.wx}`));
  equalBigInteger(pubKey.y, BigInt(`0x${key.wy}`));
  const pubR = pubKey.toRawBytes();
  for (const test of group.tests) {
    const m = CURVE.CURVE.hash(hexToBytes(test.msg));
    const { sig } = test;
    if (test.result === 'valid' || test.result === 'acceptable') {
      try {
        CURVE.Signature.fromDER(sig);
      } catch (e) {
        // Some tests has invalid signature which we don't accept
        if (e.message.includes('Invalid signature: incorrect length')) continue;
        throw e;
      }
      const verified = CURVE.verify(sig, m, pubR);
      deepStrictEqual(verified, true, `${index}: valid`);
    } else if (test.result === 'invalid') {
      let failed = false;
      try {
        failed = !CURVE.verify(sig, m, pubR);
      } catch (error) {
        failed = true;
      }
      deepStrictEqual(failed, true, `${index}: invalid`);
    } else throw new Error('unknown test result');
  }
}

describe('wycheproof ECDSA', () => {
  should('generic', () => {
    for (const group of ecdsa.testGroups) {
      let CURVE = BRAINPOOL[group.key.curve];
      if (!CURVE) continue;
      const pubKey = CURVE.ProjectivePoint.fromHex(group.key.uncompressed);
      equalBigInteger(pubKey.x, BigInt(`0x${group.key.wx}`));
      equalBigInteger(pubKey.y, BigInt(`0x${group.key.wy}`));
      for (const test of group.tests) {
        if (['Hash weaker than DL-group'].includes(test.comment)) {
          continue;
        }
        // These old Wycheproof vectors which still accept missing zero, new one is not.
        if (test.flags.includes('MissingZero') && test.result === 'acceptable')
          test.result = 'invalid';
        const m = CURVE.CURVE.hash(hexToBytes(test.msg));
        if (test.result === 'valid' || test.result === 'acceptable') {
          try {
            CURVE.Signature.fromDER(test.sig);
          } catch (e) {
            // Some test has invalid signature which we don't accept
            if (e.message.includes('Invalid signature: incorrect length')) continue;
            throw e;
          }
          const verified = CURVE.verify(test.sig, m, pubKey.toHex());
          deepStrictEqual(verified, true, `valid`);
        } else if (test.result === 'invalid') {
          let failed = false;
          try {
            failed = !CURVE.verify(test.sig, m, pubKey.toHex());
          } catch (error) {
            failed = true;
          }
          deepStrictEqual(failed, true, 'invalid');
        } else throw new Error('unknown test result');
      }
    }
  });
  for (const name in WYCHEPROOF_ECDSA) {
    const { curve, hashes } = WYCHEPROOF_ECDSA[name];
    describe(name, () => {
      for (const hName in hashes) {
        const { hash, tests } = hashes[hName];
        const CURVE = curve.create(hash);
        should(`${name}/${hName}`, () => {
          for (let i = 0; i < tests.length; i++) {
            const groups = tests[i].testGroups;
            for (let j = 0; j < groups.length; j++) {
              const group = groups[j];
              runWycheproof(name, CURVE, group, `${i}/${j}`);
            }
          }
        });
      }
    });
  }
});

const hexToBigint = (hex) => BigInteger.new(`0x${hex}`);
describe('RFC7027', () => {
  for (const v of rfc7027) {
    should(v.curve, () => {
      const curve = BRAINPOOL[v.curve];
      const secKeyA = hexToBigint(v.dA);
      const pubKeyA = curve.getPublicKey(secKeyA);
      const pubPointA = curve.ProjectivePoint.fromHex(pubKeyA);
      equalBigInteger(pubPointA.x, hexToBigint(v.QAx));
      equalBigInteger(pubPointA.y, hexToBigint(v.QAy));
      const secKeyB = hexToBigint(v.dB);
      const pubKeyB = curve.getPublicKey(secKeyB);
      const pubPointB = curve.ProjectivePoint.fromHex(pubKeyB);
      equalBigInteger(pubPointB.x, hexToBigint(v.QBx));
      equalBigInteger(pubPointB.y, hexToBigint(v.QBy));
      const shared = curve.getSharedSecret(secKeyA, pubKeyB);
      const sharedPoint = curve.ProjectivePoint.fromHex(shared);
      equalBigInteger(sharedPoint.x, hexToBigint(v.Zx));
      equalBigInteger(sharedPoint.y, hexToBigint(v.Zy));
      deepStrictEqual(shared, curve.getSharedSecret(secKeyB, pubKeyA));
    });
  }
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
