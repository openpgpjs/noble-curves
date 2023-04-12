/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { BigInteger } from '@openpgp/noble-hashes/biginteger';
import { sha256 } from '@openpgp/noble-hashes/sha256';
import { randomBytes } from '@openpgp/noble-hashes/utils';
import { Field, mod, pow2 } from './abstract/modular.js';
import { ProjPointType as PointType, mapToCurveSimpleSWU } from './abstract/weierstrass.js';
import type { Hex, PrivKey } from './abstract/utils.js';
import { bytesToNumberBE, concatBytes, ensureBytes, numberToBytesBE } from './abstract/utils.js';
import { createHasher, isogenyMap } from './abstract/hash-to-curve.js';
import { createCurve } from './_shortw_utils.js';

const secp256k1P =  Object.freeze(BigInteger.new('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'));
const secp256k1N =  Object.freeze(BigInteger.new('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'));
const _0n = Object.freeze(BigInteger.new(0));
const _1n = Object.freeze(BigInteger.new(1));
const _2n =  Object.freeze(BigInteger.new(2));
const divNearest = (a: BigInteger, b: BigInteger) => a.add( b.rightShift(_1n) ).idiv(b);

/**
 * √n = n^((p+1)/4) for fields p = 3 mod 4. We unwrap the loop and multiply bit-by-bit.
 * (P+1n/4n).toString(2) would produce bits [223x 1, 0, 22x 1, 4x 0, 11, 00]
 */
function sqrtMod(y: BigInteger): BigInteger {
  const P = secp256k1P;
  // prettier-ignore
  const _3n = BigInteger.new(3), _6n = BigInteger.new(6), _11n = BigInteger.new(11), _22n = BigInteger.new(22);
  // prettier-ignore
  const _23n = BigInteger.new(23), _44n = BigInteger.new(44), _88n = BigInteger.new(88);
  const b2 = y.mul(y).imul(y).imod(P); // x^3, 11
  const b3 = b2.mul(b2).imul(y).imod(P); // x^7
  const b6 = pow2(b3, _3n, P).imul(b3).imod(P);
  const b9 = pow2(b6, _3n, P).imul(b3).imod(P);
  const b11 = pow2(b9, _2n, P).imul(b2).imod(P);
  const b22 = pow2(b11, _11n, P).imul(b11).imod(P);
  const b44 = pow2(b22, _22n, P).imul(b22).imod(P);
  const b88 = pow2(b44, _44n, P).imul(b44).imod(P);
  const b176 = pow2(b88, _88n, P).imul(b88).imod(P);
  const b220 = pow2(b176, _44n, P).imul(b44).imod(P);
  const b223 = pow2(b220, _3n, P).imul(b3).imod(P);
  const t1 = pow2(b223, _23n, P).imul(b22).imod(P);
  const t2 = pow2(t1, _6n, P).imul(b2).imod(P);
  const root = pow2(t2, _2n, P);
  if (!Fp.eql(Fp.sqr(root), y)) throw new Error('Cannot find square root');
  return root;
}

const Fp = Field(secp256k1P, undefined, undefined, { sqrt: sqrtMod });

export const secp256k1 = createCurve(
  {
    a: BigInteger.new(0), // equation params: a, b
    b: BigInteger.new(7), // Seem to be rigid: bitcointalk.org/index.php?topic=289795.msg3183975#msg3183975
    Fp, // Field's prime: 2n**256n - 2n**32n - 2n**9n - 2n**8n - 2n**7n - 2n**6n - 2n**4n - 1n
    n: secp256k1N, // Curve order, total count of valid points in the field
    // Base point (x, y) aka generator point
    Gx: BigInteger.new('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
    Gy: BigInteger.new('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
    h: BigInteger.new(1), // Cofactor
    lowS: true, // Allow only low-S signatures by default in sign() and verify()
    /**
     * secp256k1 belongs to Koblitz curves: it has efficiently computable endomorphism.
     * Endomorphism uses 2x less RAM, speeds up precomputation by 2x and ECDH / key recovery by 20%.
     * For precomputed wNAF it trades off 1/2 init time & 1/3 ram for 20% perf hit.
     * Explanation: https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
     */
    endo: {
      beta: BigInteger.new('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
      splitScalar: (k: BigInteger) => {
        const n = secp256k1N;
        const a1 = BigInteger.new('0x3086d221a7d46bcde86c90e49284eb15');
        const b1 = _1n.negate().imul( BigInteger.new('0xe4437ed6010e88286f547fa90abfe4c3') );
        const a2 = BigInteger.new('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
        const b2 = a1;
        const POW_2_128 = BigInteger.new('0x100000000000000000000000000000000'); // (2n**128n).toString(16)

        const c1 = divNearest(b2.mul(k), n);
        const c2 = divNearest(b1.negate().imul( k ), n);
        let k1 = mod(k.sub( c1.mul(a1) ).sub( c2.mul(a2) ), n);
        let k2 = mod(c1.negate().mul(b1).isub( c2.mul(b2) ), n);
        const k1neg = k1.gt(POW_2_128);
        const k2neg = k2.gt(POW_2_128);
        if (k1neg) k1 = n.sub(k1);
        if (k2neg) k2 = n.sub(k2);
        if (k1.gt(POW_2_128) || k2.gt(POW_2_128)) {
          throw new Error('splitScalar: Endomorphism failed, k=' + k);
        }
        return { k1neg, k1, k2neg, k2 };
      },
    },
  },
  sha256
);

// Schnorr signatures are superior to ECDSA from above. Below is Schnorr-specific BIP0340 code.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
const fe = (x: BigInteger) => x instanceof BigInteger && _0n.lt(x) && x.lt(secp256k1P);
const ge = (x: BigInteger) => x instanceof BigInteger && _0n.lt(x) && x.lt(secp256k1N);
/** An object mapping tags to their tagged hash prefix of [SHA256(tag) | SHA256(tag)] */
const TAGGED_HASH_PREFIXES: { [tag: string]: Uint8Array } = {};
function taggedHash(tag: string, ...messages: Uint8Array[]): Uint8Array {
  let tagP = TAGGED_HASH_PREFIXES[tag];
  if (tagP === undefined) {
    const tagH = sha256(Uint8Array.from(tag, (c) => c.charCodeAt(0))); // TODO replace Uint8Array.from
    tagP = concatBytes(tagH, tagH);
    TAGGED_HASH_PREFIXES[tag] = tagP;
  }
  return sha256(concatBytes(tagP, ...messages));
}

// ECDSA compact points are 33-byte. Schnorr is 32: we strip first byte 0x02 or 0x03
const pointToBytes = (point: PointType<BigInteger>) => point.toRawBytes(true).slice(1);
const numTo32b = (n: BigInteger) => numberToBytesBE(n, 32);
const modP = (x: BigInteger) => mod(x, secp256k1P);
const modN = (x: BigInteger) => mod(x, secp256k1N);
const Point = secp256k1.ProjectivePoint;
const GmulAdd = (Q: PointType<BigInteger>, a: BigInteger, b: BigInteger) =>
  Point.BASE.multiplyAndAddUnsafe(Q, a, b);

// Calculate point, scalar and bytes
function schnorrGetExtPubKey(priv: PrivKey) {
  let d_ = secp256k1.utils.normPrivateKeyToScalar(priv); // same method executed in fromPrivateKey
  let p = Point.fromPrivateKey(d_); // P = d'⋅G; 0 < d' < n check is done inside
  const scalar = p.hasEvenY() ? d_ : modN(d_.negate());
  return { scalar: scalar, bytes: pointToBytes(p) };
}
/**
 * lift_x from BIP340. Convert 32-byte x coordinate to elliptic curve point.
 * @returns valid point checked for being on-curve
 */
function lift_x(x: BigInteger): PointType<BigInteger> {
  if (!fe(x)) throw new Error('bad x: need 0 < x < p'); // Fail if x ≥ p.
  const xx = modP(x.mul(x));
  const c = modP(xx.mul(x).iadd( BigInteger.new(7) )); // Let c = x³ + 7 mod p.
  let y = sqrtMod(c); // Let y = c^(p+1)/4 mod p.
  if (!y.isEven()) y = modP(y.negate()); // Return the unique point P such that x(P) = x and
  const p = new Point(x, y, _1n); // y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
  p.assertValidity();
  return p;
}
/**
 * Create tagged hash, convert it to BigInteger, reduce modulo-n.
 */
function challenge(...args: Uint8Array[]): BigInteger {
  return modN(bytesToNumberBE(taggedHash('BIP0340/challenge', ...args)));
}

/**
 * Schnorr public key is just `x` coordinate of Point as per BIP340.
 */
function schnorrGetPublicKey(privateKey: Hex): Uint8Array {
  return schnorrGetExtPubKey(privateKey).bytes; // d'=int(sk). Fail if d'=0 or d'≥n. Ret bytes(d'⋅G)
}

/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * auxRand is optional and is not the sole source of k generation: bad CSPRNG won't be dangerous.
 */
function schnorrSign(
  message: Hex,
  privateKey: PrivKey,
  auxRand: Hex = randomBytes(32)
): Uint8Array {
  const m = ensureBytes('message', message);
  const { bytes: px, scalar: d } = schnorrGetExtPubKey(privateKey); // checks for isWithinCurveOrder
  const a = ensureBytes('auxRand', auxRand, 32); // Auxiliary random data a: a 32-byte array
  const t = numTo32b(d.xor( bytesToNumberBE(taggedHash('BIP0340/aux', a)) )); // Let t be the byte-wise xor of bytes(d) and hash/aux(a)
  const rand = taggedHash('BIP0340/nonce', t, px, m); // Let rand = hash/nonce(t || bytes(P) || m)
  const k_ = modN(bytesToNumberBE(rand)); // Let k' = int(rand) mod n
  if (k_.isZero()) throw new Error('sign failed: k is zero'); // Fail if k' = 0.
  const { bytes: rx, scalar: k } = schnorrGetExtPubKey(k_); // Let R = k'⋅G.
  const e = challenge(rx, px, m); // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.
  const sig = new Uint8Array(64); // Let sig = bytes(R) || bytes((k + ed) mod n).
  sig.set(rx, 0);
  sig.set(numTo32b(modN(k.add( e.mul(d) ))), 32);
  // If Verify(bytes(P), m, sig) (see below) returns failure, abort
  if (!schnorrVerify(sig, m, px)) throw new Error('sign: Invalid signature produced');
  return sig;
}

/**
 * Verifies Schnorr signature.
 * Will swallow errors & return false except for initial type validation of arguments.
 */
function schnorrVerify(signature: Hex, message: Hex, publicKey: Hex): boolean {
  const sig = ensureBytes('signature', signature, 64);
  const m = ensureBytes('message', message);
  const pub = ensureBytes('publicKey', publicKey, 32);
  try {
    const P = lift_x(bytesToNumberBE(pub)); // P = lift_x(int(pk)); fail if that fails
    const r = bytesToNumberBE(sig.subarray(0, 32)); // Let r = int(sig[0:32]); fail if r ≥ p.
    if (!fe(r)) return false;
    const s = bytesToNumberBE(sig.subarray(32, 64)); // Let s = int(sig[32:64]); fail if s ≥ n.
    if (!ge(s)) return false;
    const e = challenge(numTo32b(r), pointToBytes(P), m); // int(challenge(bytes(r)||bytes(P)||m))%n
    const R = GmulAdd(P, s, modN(e.negate())); // R = s⋅G - e⋅P
    if (!R || !R.hasEvenY() || !R.toAffine().x.equal(r)) return false; // -eP == (n-e)P
    return true; // Fail if is_infinite(R) / not has_even_y(R) / x(R) ≠ r.
  } catch (error) {
    return false;
  }
}

export const schnorr = /* @__PURE__ */ (() => ({
  getPublicKey: schnorrGetPublicKey,
  sign: schnorrSign,
  verify: schnorrVerify,
  utils: {
    randomPrivateKey: secp256k1.utils.randomPrivateKey,
    lift_x,
    pointToBytes,
    numberToBytesBE,
    bytesToNumberBE,
    taggedHash,
    mod,
  },
}))();

const isoMap = /* @__PURE__ */ (() =>
  isogenyMap(
    Fp,
    [
      // xNum
      [
        '0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7',
        '0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581',
        '0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262',
        '0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c',
      ],
      // xDen
      [
        '0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b',
        '0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14',
        '0x0000000000000000000000000000000000000000000000000000000000000001', // LAST 1
      ],
      // yNum
      [
        '0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c',
        '0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3',
        '0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931',
        '0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84',
      ],
      // yDen
      [
        '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b',
        '0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573',
        '0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f',
        '0x0000000000000000000000000000000000000000000000000000000000000001', // LAST 1
      ],
    ].map((i) => i.map((j) => BigInteger.new(j))) as [BigInteger[], BigInteger[], BigInteger[], BigInteger[]]
  ))();
const mapSWU = /* @__PURE__ */ (() =>
  mapToCurveSimpleSWU(Fp, {
    A: BigInteger.new('0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533'),
    B: BigInteger.new('1771'),
    Z: Fp.create(BigInteger.new('-11')),
  }))();
const htf = /* @__PURE__ */ (() =>
  createHasher(
    secp256k1.ProjectivePoint,
    (scalars: BigInteger[]) => {
      const { x, y } = mapSWU(Fp.create(scalars[0]));
      return isoMap(x, y);
    },
    {
      DST: 'secp256k1_XMD:SHA-256_SSWU_RO_',
      encodeDST: 'secp256k1_XMD:SHA-256_SSWU_NU_',
      p: Fp.ORDER,
      m: 1,
      k: 128,
      expand: 'xmd',
      hash: sha256,
    }
  ))();
export const hashToCurve = /* @__PURE__ */ (() => htf.hashToCurve)();
export const encodeToCurve = /* @__PURE__ */ (() => htf.encodeToCurve)();
