import { createCurve } from './_shortw_utils.js';
import { sha256 } from '@openpgp/noble-hashes/sha256';
import { Field } from './abstract/modular.js';
import { BigInteger } from '@openpgp/noble-hashes/biginteger';

// brainpoolP256r1: https://datatracker.ietf.org/doc/html/rfc5639#section-3.4

const Fp = Field(BigInteger.new('0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377'));
const CURVE_A = Fp.create(BigInteger.new('0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9'));
const CURVE_B = BigInteger.new('0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6');

// prettier-ignore
export const brainpoolP256r1 = createCurve({
  a: CURVE_A, // Equation params: a, b
  b: CURVE_B,
  Fp,
  // Curve order (q), total count of valid points in the field
  n: BigInteger.new('0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7'),
  // Base (generator) point (x, y)
  Gx: BigInteger.new('0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262'),
  Gy: BigInteger.new('0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997'),
  h: BigInteger.new(1),
  lowS: false,
} as const, sha256);
