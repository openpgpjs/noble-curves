import { BigInteger } from '@openpgp/noble-hashes/biginteger';
import { bytesToHex as hex, hexToBytes } from '@openpgp/noble-hashes/utils';
import { deepStrictEqual, throws } from 'assert';
import { describe, should } from 'micro-should';
import { bytesToNumberLE } from '../esm/abstract/utils.js';
import { ed448, DecafPoint } from '../esm/ed448.js';

describe('decaf448', () => {
  should('follow the byte encodings of small multiples', () => {
    const encodingsOfSmallMultiples = [
      // This is the identity point
      '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      // This is the basepoint
      '6666666666666666666666666666666666666666666666666666666633333333333333333333333333333333333333333333333333333333',
      // These are small multiples of the basepoint
      'c898eb4f87f97c564c6fd61fc7e49689314a1f818ec85eeb3bd5514ac816d38778f69ef347a89fca817e66defdedce178c7cc709b2116e75',
      'a0c09bf2ba7208fda0f4bfe3d0f5b29a543012306d43831b5adc6fe7f8596fa308763db15468323b11cf6e4aeb8c18fe44678f44545a69bc',
      'b46f1836aa287c0a5a5653f0ec5ef9e903f436e21c1570c29ad9e5f596da97eeaf17150ae30bcb3174d04bc2d712c8c7789d7cb4fda138f4',
      '1c5bbecf4741dfaae79db72dface00eaaac502c2060934b6eaaeca6a20bd3da9e0be8777f7d02033d1b15884232281a41fc7f80eed04af5e',
      '86ff0182d40f7f9edb7862515821bd67bfd6165a3c44de95d7df79b8779ccf6460e3c68b70c16aaa280f2d7b3f22d745b97a89906cfc476c',
      '502bcb6842eb06f0e49032bae87c554c031d6d4d2d7694efbf9c468d48220c50f8ca28843364d70cee92d6fe246e61448f9db9808b3b2408',
      '0c9810f1e2ebd389caa789374d78007974ef4d17227316f40e578b336827da3f6b482a4794eb6a3975b971b5e1388f52e91ea2f1bcb0f912',
      '20d41d85a18d5657a29640321563bbd04c2ffbd0a37a7ba43a4f7d263ce26faf4e1f74f9f4b590c69229ae571fe37fa639b5b8eb48bd9a55',
      'e6b4b8f408c7010d0601e7eda0c309a1a42720d6d06b5759fdc4e1efe22d076d6c44d42f508d67be462914d28b8edce32e7094305164af17',
      'be88bbb86c59c13d8e9d09ab98105f69c2d1dd134dbcd3b0863658f53159db64c0e139d180f3c89b8296d0ae324419c06fa87fc7daaf34c1',
      'a456f9369769e8f08902124a0314c7a06537a06e32411f4f93415950a17badfa7442b6217434a3a05ef45be5f10bd7b2ef8ea00c431edec5',
      '186e452c4466aa4383b4c00210d52e7922dbf9771e8b47e229a9b7b73c8d10fd7ef0b6e41530f91f24a3ed9ab71fa38b98b2fe4746d51d68',
      '4ae7fdcae9453f195a8ead5cbe1a7b9699673b52c40ab27927464887be53237f7f3a21b938d40d0ec9e15b1d5130b13ffed81373a53e2b43',
      '841981c3bfeec3f60cfeca75d9d8dc17f46cf0106f2422b59aec580a58f342272e3a5e575a055ddb051390c54c24c6ecb1e0aceb075f6056',
    ];
    let B = DecafPoint.BASE;
    let P = DecafPoint.ZERO;
    for (const encoded of encodingsOfSmallMultiples) {
      deepStrictEqual(P.toHex(), encoded);
      deepStrictEqual(DecafPoint.fromHex(encoded).toHex(), encoded);
      P = P.add(B);
    }
  });
  should('not convert bad bytes encoding', () => {
    const badEncodings = [
      // These are all bad because they're non-canonical field encodings.
      '8e24f838059ee9fef1e209126defe53dcd74ef9b6304601c6966099effffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      '86fcc7212bd4a0b980928666dc28c444a605ef38e09fb569e28d4443ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      '866d54bd4c4ff41a55d4eefdbeca73cbd653c7bd3135b383708ec0bdffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      '4a380ccdab9c86364a89e77a464d64f9157538cfdfa686adc0d5ece4ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      'f22d9d4c945dd44d11e0b1d3d3d358d959b4844d83b08c44e659d79fffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      '8cdffc681aa99e9c818c8ef4c3808b58e86acdef1ab68c8477af185bffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      '0e1c12ac7b5920effbd044e897c57634e2d05b5c27f8fa3df8a086a1ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      // These are all bad because they're negative field elements.
      '15141bd2121837ef71a0016bd11be757507221c26542244f23806f3fd3496b7d4c36826276f3bf5deea2c60c4fa4cec69946876da497e795',
      '455d380238434ab740a56267f4f46b7d2eb2dd8ee905e51d7b0ae8a6cb2bae501e67df34ab21fa45946068c9f233939b1d9521a998b7cb93',
      '810b1d8e8bf3a9c023294bbfd3d905a97531709bdc0f42390feedd7010f77e98686d400c9c86ed250ceecd9de0a18888ffecda0f4ea1c60d',
      'd3af9cc41be0e5de83c0c6273bedcb9351970110044a9a41c7b9b2267cdb9d7bf4dc9c2fdb8bed32878184604f1d9944305a8df4274ce301',
      '9312bcab09009e4330ff89c4bc1e9e000d863efc3c863d3b6c507a40fd2cdefde1bf0892b4b5ed9780b91ed1398fb4a7344c605aa5efda74',
      '53d11bce9e62a29d63ed82ae93761bdd76e38c21e2822d6ebee5eb1c5b8a03eaf9df749e2490eda9d8ac27d1f71150de93668074d18d1c3a',
      '697c1aed3cd8858515d4be8ac158b229fe184d79cb2b06e49210a6f3a7cd537bcd9bd390d96c4ab6a4406da5d93640726285370cfa95df80',
      // These are all bad because they give a nonsquare x².
      '58ad48715c9a102569b68b88362a4b0645781f5a19eb7e59c6a4686fd0f0750ff42e3d7af1ab38c29d69b670f31258919c9fdbf6093d06c0',
      '8ca37ee2b15693f06e910cf43c4e32f1d5551dda8b1e48cb6ddd55e440dbc7b296b601919a4e4069f59239ca247ff693f7daa42f086122b1',
      '982c0ec7f43d9f97c0a74b36db0abd9ca6bfb98123a90782787242c8a523cdc76df14a910d54471127e7662a1059201f902940cd39d57af5',
      'baa9ab82d07ca282b968a911a6c3728d74bf2fe258901925787f03ee4be7e3cb6684fd1bcfe5071a9a974ad249a4aaa8ca81264216c68574',
      '2ed9ffe2ded67a372b181ac524996402c42970629db03f5e8636cbaf6074b523d154a7a8c4472c4c353ab88cd6fec7da7780834cc5bd5242',
      'f063769e4241e76d815800e4933a3a144327a30ec40758ad3723a788388399f7b3f5d45b6351eb8eddefda7d5bff4ee920d338a8b89d8b63',
      '5a0104f1f55d152ceb68bc138182499891d90ee8f09b40038ccc1e07cb621fd462f781d045732a4f0bda73f0b2acf94355424ff0388d4b9c',
    ];
    for (const badBytes of badEncodings) {
      const b = hexToBytes(badBytes);
      throws(() => DecafPoint.fromHex(b), badBytes);
    }
  });
  should('create right points from uniform hash', () => {
    const hashes = [
      'cbb8c991fd2f0b7e1913462d6463e4fd2ce4ccdd28274dc2ca1f4165d5ee6cdccea57be3416e166fd06718a31af45a2f8e987e301be59ae6673e963001dbbda80df47014a21a26d6c7eb4ebe0312aa6fffb8d1b26bc62ca40ed51f8057a635a02c2b8c83f48fa6a2d70f58a1185902c0',
      'b6d8da654b13c3101d6634a231569e6b85961c3f4b460a08ac4a5857069576b64428676584baa45b97701be6d0b0ba18ac28d443403b45699ea0fbd1164f5893d39ad8f29e48e399aec5902508ea95e33bc1e9e4620489d684eb5c26bc1ad1e09aba61fabc2cdfee0b6b6862ffc8e55a',
      '36a69976c3e5d74e4904776993cbac27d10f25f5626dd45c51d15dcf7b3e6a5446a6649ec912a56895d6baa9dc395ce9e34b868d9fb2c1fc72eb6495702ea4f446c9b7a188a4e0826b1506b0747a6709f37988ff1aeb5e3788d5076ccbb01a4bc6623c92ff147a1e21b29cc3fdd0e0f4',
      'd5938acbba432ecd5617c555a6a777734494f176259bff9dab844c81aadcf8f7abd1a9001d89c7008c1957272c1786a4293bb0ee7cb37cf3988e2513b14e1b75249a5343643d3c5e5545a0c1a2a4d3c685927c38bc5e5879d68745464e2589e000b31301f1dfb7471a4f1300d6fd0f99',
      '4dec58199a35f531a5f0a9f71a53376d7b4bdd6bbd2904234a8ea65bbacbce2a542291378157a8f4be7b6a092672a34d85e473b26ccfbd4cdc6739783dc3f4f6ee3537b7aed81df898c7ea0ae89a15b5559596c2a5eeacf8b2b362f3db2940e3798b63203cae77c4683ebaed71533e51',
      'df2aa1536abb4acab26efa538ce07fd7bca921b13e17bc5ebcba7d1b6b733deda1d04c220f6b5ab35c61b6bcb15808251cab909a01465b8ae3fc770850c66246d5a9eae9e2877e0826e2b8dc1bc08009590bc6778a84e919fbd28e02a0f9c49b48dc689eb5d5d922dc01469968ee81b5',
      'e9fb440282e07145f1f7f5ecf3c273212cd3d26b836b41b02f108431488e5e84bd15f2418b3d92a3380dd66a374645c2a995976a015632d36a6c2189f202fc766e1c82f50ad9189be190a1f0e8f9b9e69c9c18cc98fdd885608f68bf0fdedd7b894081a63f70016a8abf04953affbefa',
    ];
    const encodedHashToPoints = [
      '0c709c9607dbb01c94513358745b7c23953d03b33e39c7234e268d1d6e24f34014ccbc2216b965dd231d5327e591dc3c0e8844ccfd568848',
      '76ab794e28ff1224c727fa1016bf7f1d329260b7218a39aea2fdb17d8bd9119017b093d641cedf74328c327184dc6f2a64bd90eddccfcdab',
      'c8d7ac384143500e50890a1c25d643343accce584caf2544f9249b2bf4a6921082be0e7f3669bb5ec24535e6c45621e1f6dec676edd8b664',
      '62beffc6b8ee11ccd79dbaac8f0252c750eb052b192f41eeecb12f2979713b563caf7d22588eca5e80995241ef963e7ad7cb7962f343a973',
      'f4ccb31d263731ab88bed634304956d2603174c66da38742053fa37dd902346c3862155d68db63be87439e3d68758ad7268e239d39c4fd3b',
      '7e79b00e8e0a76a67c0040f62713b8b8c6d6f05e9c6d02592e8a22ea896f5deacc7c7df5ed42beae6fedb9000285b482aa504e279fd49c32',
      '20b171cb16be977f15e013b9752cf86c54c631c4fc8cbf7c03c4d3ac9b8e8640e7b0e9300b987fe0ab5044669314f6ed1650ae037db853f1',
    ];

    for (let i = 0; i < hashes.length; i++) {
      const hash = hexToBytes(hashes[i]);
      const point = DecafPoint.hashToCurve(hash);
      deepStrictEqual(point.toHex(), encodedHashToPoints[i]);
    }
  });
  should('have proper equality testing', () => {
    const MAX_448B = BigInteger.new(
      '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    );
    const bytes448ToNumberLE = (bytes) => ed448.CURVE.Fp.create(bytesToNumberLE(bytes).ibitwiseAnd(MAX_448B));

    const priv = new Uint8Array([
      23, 211, 149, 179, 209, 108, 78, 37, 229, 45, 122, 220, 85, 38, 192, 182, 96, 40, 168, 63,
      175, 194, 73, 202, 14, 175, 78, 15, 117, 175, 40, 32, 218, 221, 151, 58, 158, 91, 250, 141,
      18, 175, 191, 119, 152, 124, 223, 101, 54, 218, 76, 158, 43, 112, 151, 32,
    ]);
    const pub = DecafPoint.BASE.multiply(bytes448ToNumberLE(priv));
    deepStrictEqual(pub.equals(DecafPoint.ZERO), false);
  });
});

// ESM is broken.
import url from 'url';

if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
