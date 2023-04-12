/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { hmac } from '@openpgp/noble-hashes/hmac';
import { concatBytes, randomBytes } from '@openpgp/noble-hashes/utils';
import { weierstrass, CurveType, CurveFn } from './abstract/weierstrass.js';
import { CHash } from './abstract/utils.js';
// import { BigInteger } from '@openpgp/noble-hashes/biginteger';

// connects noble-curves to noble-hashes
export function getHash(hash: CHash) {
  return {
    hash,
    hmac: (key: Uint8Array, ...msgs: Uint8Array[]) => hmac(hash, key, concatBytes(...msgs)),
    randomBytes,
  };
}
// Same API as @noble/hashes, with ability to create curve with custom hash
type CurveDef = Readonly<Omit<CurveType, 'hash' | 'hmac' | 'randomBytes'>>;
export interface CurveFnWithCreate extends CurveFn {
  create: (hash: CHash) => CurveFn
}
export function createCurve(curveDef: CurveDef, defHash: CHash): Readonly<CurveFnWithCreate> {
  const create = (hash: CHash) => weierstrass({ ...curveDef, ...getHash(hash) });
  return Object.freeze({ ...create(defHash), create });
}
