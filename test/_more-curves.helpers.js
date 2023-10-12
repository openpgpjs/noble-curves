/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { createCurve } from '../esm/_shortw_utils.js';
import { sha224, sha256 } from '@openpgp/noble-hashes/sha256';
import { Field as Fp } from '../esm/abstract/modular.js';
import { BigInteger } from '@openpgp/noble-hashes/biginteger';

// NIST secp192r1 aka p192
// https://www.secg.org/sec2-v2.pdf, https://neuromancer.sk/std/secg/secp192r1
export const p192 = createCurve(
  {
    // Params: a, b
    a: BigInteger.new('0xfffffffffffffffffffffffffffffffefffffffffffffffc'),
    b: BigInteger.new('0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'),
    // Field over which we'll do calculations; 2n ** 192n - 2n ** 64n - 1n
    Fp: Fp(BigInteger.new('0xfffffffffffffffffffffffffffffffeffffffffffffffff')),
    // Curve order, total count of valid points in the field.
    n: BigInteger.new('0xffffffffffffffffffffffff99def836146bc9b1b4d22831'),
    // Base point (x, y) aka generator point
    Gx: BigInteger.new('0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'),
    Gy: BigInteger.new('0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811'),
    h: BigInteger.new(1),
    lowS: false,
  },
  sha256
);
export const secp192r1 = p192;

export const p224 = createCurve(
  {
    // Params: a, b
    a: BigInteger.new('0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe'),
    b: BigInteger.new('0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4'),
    // Field over which we'll do calculations;
    Fp: Fp(BigInteger.new('0xffffffffffffffffffffffffffffffff000000000000000000000001')),
    // Curve order, total count of valid points in the field
    n: BigInteger.new('0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d'),
    // Base point (x, y) aka generator point
    Gx: BigInteger.new('0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21'),
    Gy: BigInteger.new('0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34'),
    h: BigInteger.new(1),
    lowS: false,
  },
  sha224
);
export const secp224r1 = p224;
