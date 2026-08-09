/**
 * Reviewed source S and trust-pin P manifest for retained PTY evidence.
 *
 * Source S is the last reviewed benchmark source snapshot. Trust pin P is a
 * later commit that carries this manifest plus the validator and CLI code
 * whose blobs are listed below. Evidence must be generated from S and its
 * evidence checkout must descend from P before adding only the two retained
 * JSON files. This file intentionally does not pin its own blob: the trusted
 * P checkout supplies the immutable anchor and the validator compares the
 * trusted validator and CLI blobs before accepting evidence.
 */
export const PTY_BENCHMARK_TRUST_PIN_SOURCE =
  "apps/web/src/lib/terminal/pty-benchmark-trust-pin.ts" as const;

export const REVIEWED_PTY_BENCHMARK_TRUST_PIN = {
  sourceRevision:
    "8998ac6b2623f4d81c8f6a470e98ce44c0bf15f2",
  sourceTree: "80d0136509b9c0c011e712f437c7efce77edf54c",
  sourceBlobs: [
    {
      path: "apps/web/src/lib/terminal/pty-reconnect-supersession.bench.ts",
      gitBlobSha: "447124f324b805e71c1aaca393cdaa7c53429629",
      sha256:
        "882ac6fd0863e38cc29b6f74e796a533229673beac128a090f6898f85b7111ae",
    },
    {
      path: "apps/web/src/lib/terminal/pty-connecting-ownership.bench.ts",
      gitBlobSha: "f7d1b3d04696f694897f3c47ca6f9e4fd79d883e",
      sha256:
        "cdfaa883fbcf9b6397eff674dd3cac2df0e4579cf59993e88f3508a0d73202b4",
    },
    {
      path: "apps/web/src/lib/terminal/pty-transport.ts",
      gitBlobSha: "41ab670d62c6544a5c475b8bb8a46ac424549e67",
      sha256:
        "3bc4b9a7a49fa7cd2c1ad9f34ad5455157d8620f712275baa67c1ce5f1f82f57",
    },
    {
      path: "apps/web/package.json",
      gitBlobSha: "65c955971c8cfc6d797a540a206529d1a03cc3a0",
      sha256:
        "55496937f9133d4158433707347e4c725904e5c0eea9e6551bfc3e24b8ce9391",
    },
    {
      path: "apps/web/bun.lock",
      gitBlobSha: "cd68a0985fe0aabfbc8293e4040c29a1ef42ca0b",
      sha256:
        "76a2e956462387ce42f7183c2894a4e99ec3981797060001fc25ff76b996d8bf",
    },
    {
      path: "apps/web/src/lib/terminal/pty-benchmark-provenance.ts",
      gitBlobSha: "65efc760da96b532be2103ff5a75c3555ec78fd5",
      sha256:
        "0599ad00bc91539811b44955ce66778f4ae1510056ced520cc0201a487541383",
    },
  ],
  trustedCode: [
    {
      path: "apps/web/src/lib/terminal/validate-pty-benchmarks.ts",
      gitBlobSha: "74bd953ee0ba7971b58b6cb5a9c70403a148b75c",
      sha256:
        "9125acbfb9254123aa8fa1fe815a2feb0736e89345bfe23632103c9162fd05fc",
    },
    {
      path: "apps/web/src/lib/terminal/pty-benchmark-validator.ts",
      gitBlobSha: "77e25ba3f581c03e1554901a6b0741f9973cd180",
      sha256:
        "2532e787462afc70634e5152a0525ba9602fb73f284e8c5b2fb7e45e073fc483",
    },
  ],
} as const;
