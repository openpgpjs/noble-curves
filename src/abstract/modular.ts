/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Utilities for modular arithmetics and finite fields
import { BigInteger } from '@openpgp/noble-hashes/biginteger';
import {
  bitMask,
  numberToBytesBE,
  numberToBytesLE,
  bytesToNumberBE,
  bytesToNumberLE,
  ensureBytes,
  validateObject,
} from './utils.js';

const _0n = Object.freeze(BigInteger.new(0));
const _1n = Object.freeze(BigInteger.new(1));
const _2n = Object.freeze(BigInteger.new(2));
const _3n = Object.freeze(BigInteger.new(3));
const _4n = Object.freeze(BigInteger.new(4));
const _5n = Object.freeze(BigInteger.new(5));
const _8n = Object.freeze(BigInteger.new(8));
const _9n = Object.freeze(BigInteger.new(9));
const _16n = Object.freeze(BigInteger.new(16));

// Calculates a modulo b
export function mod(a: BigInteger, b: BigInteger): BigInteger {
  return a.mod(b);
}

/**
 * Efficiently raise num to power and do modular division.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * @example
 * pow(2n, 6n, 11n) // 64n % 11n == 9n
 */
// TODO: use field version && remove
export function pow(num: BigInteger, power: BigInteger, modulo: BigInteger): BigInteger {
  // if (modulo <= _0n || power < _0n) throw new Error('Expected power/modulo > 0');
  // if (modulo === _1n) return _0n;
  // let res = _1n;
  // while (power > _0n) {
  //   if (power & _1n) res = (res * num) % modulo;
  //   num = (num * num) % modulo;
  //   power >>= _1n;
  // }
  return num.modExp(power, modulo);
}

// Does x ^ (2 ^ power) mod p. pow2(30, 4) == 30 ^ (2 ^ 4)
export function pow2(x: BigInteger, power: BigInteger, modulo: BigInteger): BigInteger {
  // let res = x;
  // while (power-- > _0n) {
  //   res *= res;
  //   res %= modulo;
  // }
  // return res;

  return x.modExp(_2n.leftShift(power.dec()), modulo);
}

// Inverses number over modulo
export function invert(number: BigInteger, modulo: BigInteger): BigInteger {
  return number.modInv(modulo);
}

/**
 * Tonelli-Shanks square root search algorithm.
 * 1. https://eprint.iacr.org/2012/685.pdf (page 12)
 * 2. Square Roots from 1; 24, 51, 10 to Dan Shanks
 * Will start an infinite loop if field order P is not prime.
 * @param P field order
 * @returns function that takes field Fp (created from P) and number n
 */
export function tonelliShanks(P: BigInteger) {
  // Legendre constant: used to calculate Legendre symbol (a | p),
  // which denotes the value of a^((p-1)/2) (mod p).
  // (a | p) ≡ 1    if a is a square (mod p)
  // (a | p) ≡ -1   if a is not a square (mod p)
  // (a | p) ≡ 0    if a ≡ 0 (mod p)
  const legendreC = P.dec().rightShift(_1n);

  let Q = P.dec();
  let S = BigInteger.new(0);
  // Step 1: By factoring out powers of 2 from p - 1,
  // find q and s such that p - 1 = q*(2^s) with q odd
  while (Q.isEven()) {
    Q.irightShift(_1n);
    S.iinc();
  } 

  let Z = BigInteger.new(2);
  const Pminus1 = P.dec();
  // Step 2: Select a non-square z such that (z | p) ≡ -1 and set c ≡ zq
  while(Z.lt(P) && !pow(Z, legendreC, P).equal(Pminus1)) {
    Z.iinc();
  }

  // Fast-path
  if (S.isOne()) {
    const p1div4 = P.inc().irightShift(_2n);
    return function tonelliFast<T>(Fp: IField<T>, n: T) {
      const root = Fp.pow(n, p1div4);
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  // Slow-path
  const Q1div2 = Q.inc().irightShift(_1n);
  return function tonelliSlow<T>(Fp: IField<T>, n: T): T {
    // Step 0: Check that n is indeed a square: (n | p) should not be ≡ -1
    if (Fp.eql(Fp.pow(n, legendreC), Fp.neg(Fp.ONE))) throw new Error('Cannot find square root');
    let r = S;
    // TODO: will fail at Fp2/etc
    let g = Fp.pow(Fp.mul(Fp.ONE, Z), Q); // will update both x and b
    let x = Fp.pow(n, Q1div2); // first guess at the square root
    let b = Fp.pow(n, Q); // first guess at the fudge factor

    while (!Fp.eql(b, Fp.ONE)) {
      if (Fp.eql(b, Fp.ZERO)) return Fp.ZERO; // https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm (4. If t = 0, return r = 0)
      // Find m such b^(2^m)==1
      let m = BigInteger.new(1);
      for (let t2 = Fp.sqr(b); m.lt(r); m.iinc()) {
        if (Fp.eql(t2, Fp.ONE)) break;
        t2 = Fp.sqr(t2); // t2 *= t2
      }
      // NOTE: r-m-1 can be bigger than 32, need to convert to bigint before shift, otherwise there will be overflow
      const ge = Fp.pow(g, _1n.leftShift(r.sub(m).idec())); // ge = 2^(r-m-1)
      g = Fp.sqr(ge); // g = ge * ge
      x = Fp.mul(x, ge); // x *= ge
      b = Fp.mul(b, g); // b *= g
      r = m;
    }
    return x;
  };
}

export function FpSqrt(P: BigInteger) {
  // NOTE: different algorithms can give different roots, it is up to user to decide which one they want.
  // For example there is FpSqrtOdd/FpSqrtEven to choice root based on oddness (used for hash-to-curve).

  // P ≡ 3 (mod 4)
  // √n = n^((P+1)/4)
  if (P.mod(_4n).equal(_3n)) {
    // Not all roots possible!
    // const ORDER =
    //   0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
    // const NUM = 72057594037927816n;
    const p1div4 = P.add(_1n).irightShift(_2n); // .idiv(_4n);
    return function sqrt3mod4<T>(Fp: IField<T>, n: T) {
      const root = Fp.pow(n, p1div4);
      // Throw if root**2 != n
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  // Atkin algorithm for q ≡ 5 (mod 8), https://eprint.iacr.org/2012/685.pdf (page 10)
  if (P.mod(_8n).equal(_5n)) {
    const c1 = P.sub(_5n).irightShift(_3n);
    return function sqrt5mod8<T>(Fp: IField<T>, n: T) {
      const n2 = Fp.mul(n, _2n);
      const v = Fp.pow(n2, c1);
      const nv = Fp.mul(n, v);
      const i = Fp.mul(Fp.mul(nv, _2n), v);
      const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  // P ≡ 9 (mod 16)
  if (P.mod(_16n).equal(_9n)) {
    // NOTE: tonelli is too slow for bls-Fp2 calculations even on start
    // Means we cannot use sqrt for constants at all!
    //
    // const c1 = Fp.sqrt(Fp.negate(Fp.ONE)); //  1. c1 = sqrt(-1) in F, i.e., (c1^2) == -1 in F
    // const c2 = Fp.sqrt(c1);                //  2. c2 = sqrt(c1) in F, i.e., (c2^2) == c1 in F
    // const c3 = Fp.sqrt(Fp.negate(c1));     //  3. c3 = sqrt(-c1) in F, i.e., (c3^2) == -c1 in F
    // const c4 = (P + _7n) / _16n;           //  4. c4 = (q + 7) / 16        # Integer arithmetic
    // sqrt = (x) => {
    //   let tv1 = Fp.pow(x, c4);             //  1. tv1 = x^c4
    //   let tv2 = Fp.mul(c1, tv1);           //  2. tv2 = c1 * tv1
    //   const tv3 = Fp.mul(c2, tv1);         //  3. tv3 = c2 * tv1
    //   let tv4 = Fp.mul(c3, tv1);           //  4. tv4 = c3 * tv1
    //   const e1 = Fp.equals(Fp.square(tv2), x); //  5.  e1 = (tv2^2) == x
    //   const e2 = Fp.equals(Fp.square(tv3), x); //  6.  e2 = (tv3^2) == x
    //   tv1 = Fp.cmov(tv1, tv2, e1); //  7. tv1 = CMOV(tv1, tv2, e1)  # Select tv2 if (tv2^2) == x
    //   tv2 = Fp.cmov(tv4, tv3, e2); //  8. tv2 = CMOV(tv4, tv3, e2)  # Select tv3 if (tv3^2) == x
    //   const e3 = Fp.equals(Fp.square(tv2), x); //  9.  e3 = (tv2^2) == x
    //   return Fp.cmov(tv1, tv2, e3); //  10.  z = CMOV(tv1, tv2, e3)  # Select the sqrt from tv1 and tv2
    // }
  }

  // Other cases: Tonelli-Shanks algorithm
  return tonelliShanks(P);
}

// Little-endian check for first LE bit (last BE bit);
export const isNegativeLE = (num: BigInteger, modulo: BigInteger) => (mod(num, modulo).getBit(0) === 1);

// Field is not always over prime: for example, Fp2 has ORDER(q)=p^m
export interface IField<T> {
  ORDER: BigInteger;
  BYTES: number;
  BITS: number;
  MASK: BigInteger;
  ZERO: T;
  ONE: T;
  // 1-arg
  create: (num: T) => T;
  isValid: (num: T) => boolean;
  is0: (num: T) => boolean;
  neg(num: T): T;
  inv(num: T): T;
  sqrt(num: T): T;
  sqr(num: T): T;
  // 2-args
  eql(lhs: T, rhs: T): boolean;
  add(lhs: T, rhs: T): T;
  sub(lhs: T, rhs: T): T;
  mul(lhs: T, rhs: T | BigInteger): T;
  pow(lhs: T, power: BigInteger): T;
  div(lhs: T, rhs: T | BigInteger): T;
  // N for NonNormalized (for now)
  addN(lhs: T, rhs: T): T;
  subN(lhs: T, rhs: T): T;
  mulN(lhs: T, rhs: T | BigInteger): T;
  sqrN(num: T): T;

  // Optional
  // Should be same as sgn0 function in
  // [RFC9380](https://www.rfc-editor.org/rfc/rfc9380#section-4.1).
  // NOTE: sgn0 is 'negative in LE', which is same as odd. And negative in LE is kinda strange definition anyway.
  isOdd?(num: T): boolean; // Odd instead of even since we have it for Fp2
  // legendre?(num: T): T;
  pow(lhs: T, power: BigInteger): T;
  invertBatch: (lst: T[]) => T[];
  toBytes(num: T): Uint8Array;
  fromBytes(bytes: Uint8Array): T;
  // If c is False, CMOV returns a, otherwise it returns b.
  cmov(a: T, b: T, c: boolean): T;
}
// prettier-ignore
const FIELD_FIELDS = [
  'create', 'isValid', 'is0', 'neg', 'inv', 'sqrt', 'sqr',
  'eql', 'add', 'sub', 'mul', 'pow', 'div',
  'addN', 'subN', 'mulN', 'sqrN'
] as const;
export function validateField<T>(field: IField<T>) {
  const initial = {
    ORDER: 'BigInteger',
    MASK: 'BigInteger',
    BYTES: 'isSafeInteger',
    BITS: 'isSafeInteger',
  } as Record<string, string>;
  const opts = FIELD_FIELDS.reduce((map, val: string) => {
    map[val] = 'function';
    return map;
  }, initial);
  return validateObject(field, opts);
}

// Generic field functions
/**
 * Same as `pow` but for Fp: non-constant-time.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 */
export function FpPow<T>(f: IField<T>, num: T, power: BigInteger): T {
  // Should have same speed as pow for bigints
  // TODO: benchmark!
  if (power.isNegative()) throw new Error('Expected power > 0');
  if (power.isZero()) return f.ONE;
  if (power.isOne()) return num;
  let p = f.ONE;
  let d = num;
  while (power.gt(_0n)) {
    if (!power.isEven()) p = f.mul(p, d);
    d = f.sqr(d);
    power = power.rightShift(_1n);
  }
  return p;
}

/**
 * Efficiently invert an array of Field elements.
 * `inv(0)` will return `undefined` here: make sure to throw an error.
 */
export function FpInvertBatch<T>(f: IField<T>, nums: T[]): T[] {
  const tmp = new Array(nums.length);
  // Walk from first to last, multiply them by each other MOD p
  const lastMultiplied = nums.reduce((acc, num, i) => {
    if (f.is0(num)) return acc;
    tmp[i] = acc;
    return f.mul(acc, num);
  }, f.ONE);
  // Invert last element
  const inverted = f.inv(lastMultiplied);
  // Walk from last to first, multiply them by inverted each other MOD p
  nums.reduceRight((acc, num, i) => {
    if (f.is0(num)) return acc;
    tmp[i] = f.mul(acc, tmp[i]);
    return f.mul(acc, num);
  }, inverted);
  return tmp;
}

export function FpDiv<T>(f: IField<T>, lhs: T, rhs: T | BigInteger): T {
  return f.mul(lhs, rhs instanceof BigInteger ? invert(rhs, f.ORDER) : f.inv(rhs));
}

// This function returns True whenever the value x is a square in the field F.
export function FpIsSquare<T>(f: IField<T>) {
  const legendreConst = f.ORDER.dec().irightShift(_1n); // Integer arithmetic
  return (x: T): boolean => {
    const p = f.pow(x, legendreConst);
    return f.eql(p, f.ZERO) || f.eql(p, f.ONE);
  };
}

// CURVE.n lengths
export function nLength(n: BigInteger, nBitLength?: number) {
  // Bit size, byte size of CURVE.n
  const _nBitLength = nBitLength !== undefined ? nBitLength : n.bitLength();
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}

type FpField = IField<BigInteger> & Required<Pick<IField<BigInteger>, 'isOdd'>>;
/**
 * Initializes a finite field over prime. **Non-primes are not supported.**
 * Do not init in loop: slow. Very fragile: always run a benchmark on a change.
 * Major performance optimizations:
 * * a) denormalized operations like mulN instead of mul
 * * b) same object shape: never add or remove keys
 * * c) Object.freeze
 * @param ORDER prime positive bigint
 * @param bitLen how many bits the field consumes
 * @param isLE (def: false) if encoding / decoding should be in little-endian
 * @param redef optional faster redefinitions of sqrt and other methods
 */
export function Field(
  ORDER: BigInteger,
  bitLen?: number,
  isLE = false,
  redef: Partial<IField<BigInteger>> = {}
): Readonly<FpField> {
  if (ORDER.lte(_0n)) throw new Error(`Expected Field ORDER > 0, got ${ORDER}`);
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, bitLen);
  if (BYTES > 2048) throw new Error('Field lengths over 2048 bytes are not supported');
  const sqrtP = FpSqrt(ORDER);
  const f: Readonly<FpField> = Object.freeze({
    ORDER,
    BITS,
    BYTES,
    MASK: bitMask(BITS),
    ZERO: _0n,
    ONE: _1n,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (!(num instanceof BigInteger))
        throw new Error(`Invalid field element: expected bigint, got ${typeof num}`);
      return _0n.lte(num) && num.lt(ORDER); // 0 is valid element, but it's not invertible
    },
    is0: (num) => num.isZero(),
    isOdd: (num) => !num.isEven(),
    neg: (num) => mod(num.negate(), ORDER),
    eql: (lhs, rhs) => lhs.equal(rhs),

    sqr: (num) => mod(num.mul(num), ORDER),
    add: (lhs, rhs) => mod(lhs.add(rhs), ORDER),
    sub: (lhs, rhs) => mod(lhs.sub(rhs), ORDER),
    mul: (lhs, rhs) => mod(lhs.mul(rhs), ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs.mul(invert(rhs, ORDER)), ORDER),

    // Same as above, but doesn't normalize
    sqrN: (num) => num.mul(num),
    addN: (lhs, rhs) => lhs.add(rhs),
    subN: (lhs, rhs) => lhs.sub(rhs),
    mulN: (lhs, rhs) => lhs.mul(rhs),

    inv: (num) => invert(num, ORDER),
    sqrt: redef.sqrt || ((n) => sqrtP(f, n)),
    invertBatch: (lst) => FpInvertBatch(f, lst),
    // TODO: do we really need constant cmov?
    // We don't have const-time bigints anyway, so probably will be not very useful
    cmov: (a, b, c) => (c ? b : a),
    toBytes: (num) => (isLE ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES)),
    fromBytes: (bytes) => {
      if (bytes.length !== BYTES)
        throw new Error(`Fp.fromBytes: expected ${BYTES}, got ${bytes.length}`);
      return isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    },
  } as FpField);
  return Object.freeze(f);
}

export function FpSqrtOdd<T>(Fp: IField<T>, elm: T) {
  if (!Fp.isOdd) throw new Error(`Field doesn't have isOdd`);
  const root = Fp.sqrt(elm);
  return Fp.isOdd(root) ? root : Fp.neg(root);
}

export function FpSqrtEven<T>(Fp: IField<T>, elm: T) {
  if (!Fp.isOdd) throw new Error(`Field doesn't have isOdd`);
  const root = Fp.sqrt(elm);
  return Fp.isOdd(root) ? Fp.neg(root) : root;
}

/**
 * "Constant-time" private key generation utility.
 * Same as mapKeyToField, but accepts less bytes (40 instead of 48 for 32-byte field).
 * Which makes it slightly more biased, less secure.
 * @deprecated use mapKeyToField instead
 */
export function hashToPrivateScalar(
  hash: string | Uint8Array,
  groupOrder: BigInteger,
  isLE = false
): BigInteger {
  hash = ensureBytes('privateHash', hash);
  const hashLen = hash.length;
  const minLen = nLength(groupOrder).nByteLength + 8;
  if (minLen < 24 || hashLen < minLen || hashLen > 1024)
    throw new Error(`hashToPrivateScalar: expected ${minLen}-1024 bytes of input, got ${hashLen}`);
  const num = isLE ? bytesToNumberLE(hash) : bytesToNumberBE(hash);
  return mod(num, groupOrder.dec()).inc();
}

/**
 * Returns total number of bytes consumed by the field element.
 * For example, 32 bytes for usual 256-bit weierstrass curve.
 * @param fieldOrder number of field elements, usually CURVE.n
 * @returns byte length of field
 */
export function getFieldBytesLength(fieldOrder: BigInteger): number {
  if (!(fieldOrder instanceof BigInteger)) throw new Error('field order must be bigint');
  return fieldOrder.byteLength();
}

/**
 * Returns minimal amount of bytes that can be safely reduced
 * by field order.
 * Should be 2^-128 for 128-bit curve such as P256.
 * @param fieldOrder number of field elements, usually CURVE.n
 * @returns byte length of target hash
 */
export function getMinHashLength(fieldOrder: BigInteger): number {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}

/**
 * "Constant-time" private key generation utility.
 * Can take (n + n/2) or more bytes of uniform input e.g. from CSPRNG or KDF
 * and convert them into private scalar, with the modulo bias being negligible.
 * Needs at least 48 bytes of input for 32-byte private key.
 * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
 * FIPS 186-5, A.2 https://csrc.nist.gov/publications/detail/fips/186/5/final
 * RFC 9380, https://www.rfc-editor.org/rfc/rfc9380#section-5
 * @param hash hash output from SHA3 or a similar function
 * @param groupOrder size of subgroup - (e.g. secp256k1.CURVE.n)
 * @param isLE interpret hash bytes as LE num
 * @returns valid private scalar
 */
export function mapHashToField(key: Uint8Array, fieldOrder: BigInteger, isLE = false): Uint8Array {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  // No small numbers: need to understand bias story. No huge numbers: easier to detect JS timings.
  if (len < 16 || len < minLen || len > 1024)
    throw new Error(`expected ${minLen}-1024 bytes of input, got ${len}`);
  const num = isLE ? bytesToNumberBE(key) : bytesToNumberLE(key);
  // `mod(x, 11)` can sometimes produce 0. `mod(x, 10) + 1` is the same, but no 0
  const reduced = mod(num, fieldOrder.dec()).inc();
  return isLE ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}
