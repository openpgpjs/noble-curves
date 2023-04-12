/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { BigInteger } from '@openpgp/noble-hashes/biginteger';
import { mod, pow } from './modular.js';
import { bytesToNumberLE, ensureBytes, numberToBytesLE, validateObject } from './utils.js';

const _0n = Object.freeze(BigInteger.new(0));
const _1n = Object.freeze(BigInteger.new(1));
const _2n = Object.freeze(BigInteger.new(2));
type Hex = string | Uint8Array;

export type CurveType = {
  P: BigInteger; // finite field prime
  nByteLength: number;
  adjustScalarBytes?: (bytes: Uint8Array) => Uint8Array;
  domain?: (data: Uint8Array, ctx: Uint8Array, phflag: boolean) => Uint8Array;
  a: BigInteger;
  montgomeryBits: number;
  powPminus2?: (x: BigInteger) => BigInteger;
  xyToU?: (x: BigInteger, y: BigInteger) => BigInteger;
  Gu: BigInteger;
  randomBytes?: (bytesLength?: number) => Uint8Array;
};
export type CurveFn = {
  scalarMult: (scalar: Hex, u: Hex) => Uint8Array;
  scalarMultBase: (scalar: Hex) => Uint8Array;
  getSharedSecret: (privateKeyA: Hex, publicKeyB: Hex) => Uint8Array;
  getPublicKey: (privateKey: Hex) => Uint8Array;
  utils: { randomPrivateKey: () => Uint8Array };
  GuBytes: Uint8Array;
};

function validateOpts(curve: CurveType) {
  validateObject(
    curve,
    {
      a: 'BigInteger',
    },
    {
      montgomeryBits: 'isSafeInteger',
      nByteLength: 'isSafeInteger',
      adjustScalarBytes: 'function',
      domain: 'function',
      powPminus2: 'function',
      Gu: 'BigInteger',
    }
  );
  // Set defaults
  return Object.freeze({ ...curve } as const);
}

// NOTE: not really montgomery curve, just bunch of very specific methods for X25519/X448 (RFC 7748, https://www.rfc-editor.org/rfc/rfc7748)
// Uses only one coordinate instead of two
export function montgomery(curveDef: CurveType): CurveFn {
  const CURVE = validateOpts(curveDef);
  const { P } = CURVE;
  const modP = (n: BigInteger) => mod(n, P);
  const montgomeryBits = CURVE.montgomeryBits;
  const montgomeryBytes = Math.ceil(montgomeryBits / 8);
  const fieldLen = CURVE.nByteLength;
  const adjustScalarBytes = CURVE.adjustScalarBytes || ((bytes: Uint8Array) => bytes);
  const powPminus2 = CURVE.powPminus2 || ((x: BigInteger) => pow(x, P.sub(_2n), P));

  // cswap from RFC7748. But it is not from RFC7748!
  /*
    cswap(swap, x_2, x_3):
         dummy = mask(swap) AND (x_2 XOR x_3)
         x_2 = x_2 XOR dummy
         x_3 = x_3 XOR dummy
         Return (x_2, x_3)
  Where mask(swap) is the all-1 or all-0 word of the same length as x_2
   and x_3, computed, e.g., as mask(swap) = 0 - swap.
  */
  function cswap(swap: BigInteger, x_2: BigInteger, x_3: BigInteger): [BigInteger, BigInteger] {
    const dummy = modP(swap.mul(x_2.sub(x_3)));
    x_2 = modP(x_2.sub(dummy));
    x_3 = modP(x_3.add(dummy));
    return [x_2, x_3];
  }

  // Accepts 0 as well
  function assertFieldElement(n: BigInteger): BigInteger {
    if (n instanceof BigInteger && !n.isNegative() && n.lt(P)) return n;
    throw new Error('Expected valid scalar 0 < scalar < CURVE.P');
  }

  // x25519 from 4
  // The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519
  const a24 = CURVE.a.sub(_2n).irightShift(_2n);
  /**
   *
   * @param pointU u coordinate (x) on Montgomery Curve 25519
   * @param scalar by which the point would be multiplied
   * @returns new Point on Montgomery curve
   */
  function montgomeryLadder(pointU: BigInteger, scalar: BigInteger): BigInteger {
    const u = assertFieldElement(pointU);
    // Section 5: Implementations MUST accept non-canonical values and process them as
    // if they had been reduced modulo the field prime.
    const k = assertFieldElement(scalar);
    const x_1 = u;
    let x_2 = _1n;
    let z_2 = _0n;
    let x_3 = u;
    let z_3 = _1n;
    let swap = _0n.clone();
    let sw: [BigInteger, BigInteger];
    for (let t = BigInteger.new(montgomeryBits - 1); !t.isNegative(); t.idec()) {
      const k_t = BigInteger.new((k.rightShift(t)).getBit(0));
      swap.ixor(k_t);
      sw = cswap(swap, x_2, x_3);
      x_2 = sw[0];
      x_3 = sw[1];
      sw = cswap(swap, z_2, z_3);
      z_2 = sw[0];
      z_3 = sw[1];
      swap = k_t;

      const A = x_2.add(z_2);
      const AA = modP(A.mul(A));
      const B = x_2.sub(z_2);
      const BB = modP(B.mul(B));
      const E = AA.sub(BB);
      const C = x_3.add(z_3);
      const D = x_3.sub(z_3);
      const DA = modP(D.mul(A));
      const CB = modP(C.mul(B));
      const dacb = DA.add(CB);
      const da_cb = DA.sub(CB);
      x_3 = modP(dacb.mul(dacb));
      z_3 = modP(x_1.mul(
          modP(da_cb.mul(da_cb))));
      x_2 = modP(AA.mul(BB));
      z_2 = modP(E.mul(
        AA.add(modP(a24.mul(E)))));
    }
    // (x_2, x_3) = cswap(swap, x_2, x_3)
    sw = cswap(swap, x_2, x_3);
    x_2 = sw[0];
    x_3 = sw[1];
    // (z_2, z_3) = cswap(swap, z_2, z_3)
    sw = cswap(swap, z_2, z_3);
    z_2 = sw[0];
    z_3 = sw[1];
    // z_2^(p - 2)
    const z2 = powPminus2(z_2);
    // Return x_2 * (z_2^(p - 2))
    return modP(x_2.mul(z2));
  }

  function encodeUCoordinate(u: BigInteger): Uint8Array {
    return numberToBytesLE(modP(u), montgomeryBytes);
  }

  function decodeUCoordinate(uEnc: Hex): BigInteger {
    // Section 5: When receiving such an array, implementations of X25519
    // MUST mask the most significant bit in the final byte.
    // This is very ugly way, but it works because fieldLen-1 is outside of bounds for X448, so this becomes NOOP
    // fieldLen - scalaryBytes = 1 for X448 and = 0 for X25519
    const u = ensureBytes('u coordinate', uEnc, montgomeryBytes);
    // u[fieldLen-1] crashes QuickJS (TypeError: out-of-bound numeric index)
    if (fieldLen === montgomeryBytes) u[fieldLen - 1] &= 127; // 0b0111_1111
    return bytesToNumberLE(u);
  }
  function decodeScalar(n: Hex): BigInteger {
    const bytes = ensureBytes('scalar', n);
    if (bytes.length !== montgomeryBytes && bytes.length !== fieldLen)
      throw new Error(`Expected ${montgomeryBytes} or ${fieldLen} bytes, got ${bytes.length}`);
    return bytesToNumberLE(adjustScalarBytes(bytes));
  }
  function scalarMult(scalar: Hex, u: Hex): Uint8Array {
    const pointU = decodeUCoordinate(u);
    const _scalar = decodeScalar(scalar);
    const pu = montgomeryLadder(pointU, _scalar);
    // The result was not contributory
    // https://cr.yp.to/ecdh.html#validate
    if (pu.isZero()) throw new Error('Invalid private or public key received');
    return encodeUCoordinate(pu);
  }
  // Computes public key from private. By doing scalar multiplication of base point.
  const GuBytes = encodeUCoordinate(CURVE.Gu);
  function scalarMultBase(scalar: Hex): Uint8Array {
    return scalarMult(scalar, GuBytes);
  }

  return {
    scalarMult,
    scalarMultBase,
    getSharedSecret: (privateKey: Hex, publicKey: Hex) => scalarMult(privateKey, publicKey),
    getPublicKey: (privateKey: Hex): Uint8Array => scalarMultBase(privateKey),
    utils: { randomPrivateKey: () => CURVE.randomBytes!(CURVE.nByteLength) },
    GuBytes: GuBytes,
  };
}
