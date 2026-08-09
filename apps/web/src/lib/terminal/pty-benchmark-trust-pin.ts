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
    "6732e2e70b22ab17830a9a18f5c34cca3258e535",
  sourceTree: "51a70bebf55c99c763d6df9122100e55ca757a88",
  sourceBlobs: [
    {
      path: "apps/web/src/lib/terminal/pty-reconnect-supersession.bench.ts",
      gitBlobSha: "d81a485c07cd5c19ad3bb76fc12d143a6e7b97de",
      sha256:
        "9b89e8f1c181f2c60b33b617b89b0d8cf71e628a978fa2b92a035162bee73d82",
    },
    {
      path: "apps/web/src/lib/terminal/pty-connecting-ownership.bench.ts",
      gitBlobSha: "87dd66aac39b4374eb6a49da9c2b45b2d039aebc",
      sha256:
        "46c0fa79e0e17289ebf604070619c0c9ac3b5fe067dea2ead31ad1efde611f38",
    },
    {
      path: "apps/web/src/lib/terminal/pty-transport.ts",
      gitBlobSha: "bf2f2a9fd540118b0630e76ae2ce4d902401417b",
      sha256:
        "30e1d44b6161147848c5e43110290bcc92b09a75ee2471729389d3adab4b4a0c",
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
      gitBlobSha: "382253ef0a9bbed0704cea5f2d0adc9e76e8eed4",
      sha256:
        "c067fdcc999b90a361a2a0a1c0b23ba3a963a30ce42557e382a76ea29fefebc7",
    },
    {
      path: "apps/web/src/lib/terminal/pty-benchmark-validator.ts",
      gitBlobSha: "77e25ba3f581c03e1554901a6b0741f9973cd180",
      sha256:
        "2532e787462afc70634e5152a0525ba9602fb73f284e8c5b2fb7e45e073fc483",
    },
  ],
} as const;
