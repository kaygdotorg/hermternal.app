# Task #409 Final Guarded Replay Execution Matrix

Artifact task #464. Corrected final matrix for a guarded, offline replay.

## Status and boundary

This artifact replaces stale exclusive ranges and marker/watermark placeholders with exact current inputs. It preserves ordered Task #409 lanes, source metadata, stable patch IDs, path allowlists, semantic projections, historical compatibility objects, and final blob checks.

Artifact production did not fetch, create a worktree, apply a patch, replay, commit, push, contact a live service, use credentials, start Hermes, open a socket, or capture a screenshot.

The expected reviewed `scripts/README.md` merge blob was not present as a stored local Git object. The source bytes were composed and verified offline; future replay must materialize and validate the same target before updating the index.

## Fixed base and notation

| Item | Exact value |
|---|---|
| Base ref | `origin/dev` |
| Base commit | `729f2613af2b78d58b07918478e9102d5716f367` |
| Base tree | `43f86b645fc9f89d5d4aa1e6978b1f61f0b5c69f` |
| Protected main | `origin/main` at `3ebf8b3fe4767442490ab3053c0c1ccf84e8019f` |

Use `A^..B` for every counted inclusive range. Use a semantic delta as content from a source parent/child pair, limited to the approved paths, without importing source ancestry. Whole-tree equality with a source tree is invalid because unrelated lanes remain.

## Ordered lanes

| # | Lane | Kind | Source | Paths | Ordering rule |
|---:|---|---|---|---:|---|
| 1 | Renderer lifecycle | `approved-range-plus-semantic-delta` | `013ea2ef992bc309290efe6f8d899a4c85381f80^..5559e9ad4cf78debc98e8935c47cdc956535f96c` | 4 |  |
| 2 | Static manifest chain | `ordered-commit-range` | `822b9668577f8f0f983abde6f00423c586042823^..e664505c7ad9779855a394c62f72823fad7eba76` | 5 |  |
| 3 | Authentication design-token manifest | `ordered-commit-range` | `07b7c06102677b4db35265958067f41fd19fa206^..d88cd9adfcef94980ae674f40d99c65e1cf9b666` | 5 |  |
| 4 | Authentication semantic delta | `semantic-content-projection` | `f87ce048b5afc4fad7ac361baa589d47745b580b → 83c709bf9a22672362662f7c369b2c235f5859e9` | 23 |  |
| 5 | Fixture-registry authority | `authority-range-plus-detached-correction` | `5e36276a27bf0f241d6a860a2cf2c865dc97be83^..a88dd1233c01f780544d563b2a030fdd1cfd0c0f` | 12 |  |
| 6 | Apple benchmark range | `ordered-commit-range` | `1f5c2f5282b1be0fdbac508749e99b5e790d3a9b^..8be4f513286813a7a1cbe7bbc997f53b7d557209` | 10 |  |
| 7 | Proxy and deployment proof | `ordered-commit-range` | `1ffc341888ea6f22bbaad42b5f989038213d72d4^..e3a2d2e662f2e606f318d35f4fccc63ba9738f7c` | 10 | First live-overlap lane |
| 8 | Launcher semantic projection replacing marker placeholder | `cumulative-semantic-projection` | `d3c40687659ee645a5f03bc80cbf61ec8c49979a` | 11 | After proxy; exclude scripts/README.md |
| 9 | Dependency audit correction | `single-semantic-commit` | `a2a8a0b03f515409a02e6668d2600e5ebb6e5152` | 3 |  |
| 10 | Swift parity correction | `direct-source-plus-semantic-child` | `221620c04bb051f2597c52bdeb16ccc55c5b2e9c → 027806c8596f8b9a4ce200b2fe1344e013f46685` | 3 |  |
| 11 | Live-proof cumulative semantic projection replacing watermark placeholder | `cumulative-semantic-projection` | `d3c40687659ee645a5f03bc80cbf61ec8c49979a → 80fe3b68fb676a3b6589fce9aed79140bf37b667` | 22 | After launcher; exact d3 overlaps |

## Lane details

### 1. Renderer lifecycle

- Exact inclusive range: `013ea2ef992bc309290efe6f8d899a4c85381f80^..5559e9ad4cf78debc98e8935c47cdc956535f96c`. Only this full canonical range is executable; abbreviated range references are rejected.
- Count: `3`; merge commits: `0`.
- Cumulative stable patch ID: `09aa5f26124fb6751f42fb168501eef0a45eb33d`.
- Path count: `4`.

Owned paths:

- `apps/web/src/lib/terminal/README.md`
- `apps/web/src/lib/terminal/renderer.test.ts`
- `apps/web/tests/bench/terminal-renderer.bench.ts`
- `apps/web/tests/bench/terminal-renderer.provenance.ts`

Source ledger:

| Commit | Parent(s) | Tree | Stable patch ID | Subject |
|---|---|---|---|---|
| `013ea2ef992bc309290efe6f8d899a4c85381f80` | `48739cde1007d830b830ff2cec1bc469de054d44` | `b0df525168205e2433c3e1ab94b94ccdbac9beb8` | `02151b1045a10bc4250ecdf899fd6b1fe7fbd3a3` | fix(terminal): require immediate evidence child |
| `4b2ca9df19f42f332ef726017af6682108ab7a66` | `013ea2ef992bc309290efe6f8d899a4c85381f80` | `3abc812e25d701b381dae04ea9e4e2c8cb54985f` | `d504306d9d6719d6eb05fe58d87b972fda5347d8` | fix(terminal): harden benchmark recomputation boundaries |
| `5559e9ad4cf78debc98e8935c47cdc956535f96c` | `4b2ca9df19f42f332ef726017af6682108ab7a66` | `8122900638aa0a1fcad57653328ade07631f4f75` | `da14a8927791a29bbf989f848010e3bf4702bcd3` | fix(terminal): close detached benchmark cleanup gaps |

- Semantic delta: `Δ(9d9756b2a0a20130258766ea3a532c067e2f13f6, befb8c7e673157932f5f13242d863e64806cffac)`.
- Parent tree: `e7208548cdb9e8cbc05938acd7126d484f0c7257`.
- Child tree: `e7af1ae07ef9c5d79d30d64b380da20bd5998651`.
- Stable patch ID: `765ab638cb0065dc7aa0291925fc86e59720af35`.

Delta paths:

- `apps/web/src/lib/terminal/renderer.test.ts`

Rejected sources:

- `9d9756b2a0a20130258766ea3a532c067e2f13f6`

Use the approved child content without inheriting rejected renderer ancestry.

### 2. Static manifest chain

- Exact inclusive range: `822b9668577f8f0f983abde6f00423c586042823^..e664505c7ad9779855a394c62f72823fad7eba76`. Only this full canonical range is executable; abbreviated range references are rejected.
- Count: `3`; merge commits: `0`.
- Cumulative stable patch ID: `def1758bc0ad4ad4a332bd19104656eac8326dbc`.
- Path count: `5`.

Owned paths:

- `apps/web/README.md`
- `apps/web/package.json`
- `apps/web/tests/static/assert-static-build.mjs`
- `apps/web/tests/static/terminal-only-manifest.mjs`
- `apps/web/tests/static/terminal-only-manifest.test.mjs`

Source ledger:

| Commit | Parent(s) | Tree | Stable patch ID | Subject |
|---|---|---|---|---|
| `822b9668577f8f0f983abde6f00423c586042823` | `729f2613af2b78d58b07918478e9102d5716f367` | `39975d2e03c13762e906ab9eb760f422d70a3147` | `bdaad5f19a9612a8cfceb3462d6c6a888a3aa1a5` | fix(web): canonicalize static terminal manifest paths |
| `28d4fb90bfe07f508ca296e9308c2efd183ec7f5` | `822b9668577f8f0f983abde6f00423c586042823` | `f2db122ea16638ca4234d658fc38fef3d083031f` | `1092987401f94a67ea833a9ae6d759f4d214263a` | fix(web): reject unsafe terminal manifest aliases |
| `e664505c7ad9779855a394c62f72823fad7eba76` | `28d4fb90bfe07f508ca296e9308c2efd183ec7f5` | `14ca3391fb16f5020ef3161c4d50d75be98bc1bc` | `afb6f8f9bb9dcd887cee42aa00c7b0fe3ee6901c` | fix(web): claim normalized terminal manifest aliases |

Apply these commits in this order and do not reorder:

- `822b9668577f8f0f983abde6f00423c586042823`
- `28d4fb90bfe07f508ca296e9308c2efd183ec7f5`
- `e664505c7ad9779855a394c62f72823fad7eba76`

### 3. Authentication design-token manifest

- Exact inclusive range: `07b7c06102677b4db35265958067f41fd19fa206^..d88cd9adfcef94980ae674f40d99c65e1cf9b666`.
- Count: `3`; merge commits: `0`.
- Cumulative stable patch ID: `45ea487a2dd2080df5bcd0d8fb1a39cead6f2bfd`.
- Path count: `5`.

Owned paths:

- `contracts/design-tokens/README.md`
- `contracts/design-tokens/web/README.md`
- `contracts/design-tokens/web/artboards.json`
- `contracts/design-tokens/web/test_validate.py`
- `contracts/design-tokens/web/validate.py`

Source ledger:

| Commit | Parent(s) | Tree | Stable patch ID | Subject |
|---|---|---|---|---|
| `07b7c06102677b4db35265958067f41fd19fa206` | `abfe3fca3767fbfce724beb3ecde2ceb65f676ef` | `0b99f2743fd401cd18cc48355f9d3852d0847e06` | `4f27b0ab5a9d6f7f5804db2d2428673d674d8751` | fix(design-tokens): register approved authentication boards |
| `9a6587741ab46b067d620aea3dc7e885abd2ec80` | `07b7c06102677b4db35265958067f41fd19fa206` | `cac1d57e79f601aa3f184506a8b35252d0883030` | `18507fd903b8f0b4c834aaa9c13a24a7cdcdee84` | fix(design-tokens): align Paper page sources |
| `d88cd9adfcef94980ae674f40d99c65e1cf9b666` | `9a6587741ab46b067d620aea3dc7e885abd2ec80` | `a11efeae95cbb0da0c08974786db287a1d150eb4` | `8e269183927a86b10775cc8856604e64dde727ca` | test(design-tokens): guard Authentication page provenance |

### 4. Authentication semantic delta

- Semantic delta: `Δ(f87ce048b5afc4fad7ac361baa589d47745b580b, 83c709bf9a22672362662f7c369b2c235f5859e9)`.
- Parent tree: `709ca54ce7810ee109712abf41c4793fc2d5ef7a`.
- Child tree: `c23474de976cbd12497fc109db9acdac62966ec0`.
- Stable patch ID: `261363bf146f59c9f33d97728034c84acbccf90a`.

Delta paths:

- `apps/web/src/lib/auth-ui/AuthPreview.svelte`
- `apps/web/src/lib/auth-ui/AuthPreview.test.ts`

Reviewed ownership set:

- `apps/web/src/lib/auth-ui/AuthPreview.svelte`
- `apps/web/src/lib/auth-ui/AuthPreview.test.ts`
- `apps/web/src/lib/auth-ui/BrowserAuthView.svelte`
- `apps/web/src/lib/auth-ui/BrowserAuthView.test.ts`
- `apps/web/src/lib/auth-ui/ProviderCard.svelte`
- `apps/web/src/lib/auth-ui/ProviderCard.test.ts`
- `apps/web/src/lib/auth-ui/browser-auth-session.test.ts`
- `apps/web/src/lib/auth-ui/browser-auth.md`
- `apps/web/src/lib/auth-ui/fixtures.ts`
- `apps/web/src/lib/auth-ui/types.ts`
- `apps/web/src/lib/root-route.test.ts`
- `apps/web/src/lib/root-route.ts`
- `apps/web/src/lib/workspace/Composer.svelte`
- `apps/web/src/lib/workspace/Composer.test.ts`
- `apps/web/src/lib/workspace/LiveWorkspaceView.svelte`
- `apps/web/src/lib/workspace/LiveWorkspaceView.test.ts`
- `apps/web/src/lib/workspace/WorkspacePreview.svelte`
- `apps/web/src/lib/workspace/WorkspacePreview.test.ts`
- `apps/web/src/lib/workspace/live-workspace-session.test.ts`
- `apps/web/src/lib/workspace/live-workspace-session.ts`
- `apps/web/src/routes/ui-preview/+page.svelte`
- `apps/web/src/routes/ui-preview/ui-preview.test.ts`
- `apps/web/tests/e2e/ui-preview.spec.ts`

Rehearsal oracle: `b1741699ca93262306b039771fe96282cb4142fd`; parent `1f4388b24ccf7ebc3c42b2192515ae343a52083a`; tree `54916a4a3baad005631cd6c5193392d44010c60e`; stable patch ID `313527664bea572980abed8c0dee582f931597ce`. This validates semantic content; it is not product ancestry.

### 5. Fixture-registry authority

- Exact inclusive range: `5e36276a27bf0f241d6a860a2cf2c865dc97be83^..a88dd1233c01f780544d563b2a030fdd1cfd0c0f`. Only this full canonical range is executable; abbreviated range references are rejected.
- Count: `10`; merge commits: `0`.
- Cumulative stable patch ID: `f6f3c7fc60d8c9f391dbeba88fcfd9df6dc5bb4f`.
- Path count: `12`.

Owned paths:

- `contracts/fixtures/README.md`
- `contracts/fixtures/index.json`
- `contracts/fixtures/validator/test_validate.py`
- `contracts/fixtures/validator/validate.py`
- `contracts/fixtures/validator/validation-baseline.json`
- `docs/architecture/fixture-registry-authority.md`
- `scripts/fixture_authority_test_source.py`
- `scripts/fixture_registry_authority.objects.bundle`
- `scripts/fixture_registry_authority.v2.hardened.json`
- `scripts/fixture_registry_authority.v2.hardened.pin.json`
- `scripts/test_fixture_registry_authority.py`
- `scripts/verify_fixture_registry_authority.py`

Source ledger:

| Commit | Parent(s) | Tree | Stable patch ID | Subject |
|---|---|---|---|---|
| `5e36276a27bf0f241d6a860a2cf2c865dc97be83` | `5997b9e9cd84d3ac07df28c030f3eea6072219aa` | `878c8590ba55be3c67347a8f8e12808e04e2dec2` | `f645d9212aee1652b24000f2ebd71887aada38d3` | fix(fixtures): complete aggregate registry predecessor |
| `240b3f6dc16ee7cad3d5287a79dcf64f26e9d38c` | `5e36276a27bf0f241d6a860a2cf2c865dc97be83` | `3ad3b1e708001d338a36246d8fbe05a70b8815a4` | `47d1bad8b75f709649a79cb7d82ead77ead9e430` | fix(fixtures): close validator scanner alias gaps |
| `d258ac3164be8d3b967bf6c41a96f2f581742844` | `240b3f6dc16ee7cad3d5287a79dcf64f26e9d38c` | `d1fdebe885f6fbc9e47522102f9287734ad31d07` | `72c1a898456fa5f5caa8e1bbe4d91ad9813782ec` | fix(fixtures): harden aggregate registry controls |
| `8e388b6f78619d3679fc14f445bc2267673e1a1e` | `d258ac3164be8d3b967bf6c41a96f2f581742844` | `fe1c54e65c103d279ccd8459dcef17c4bdca5d94` | `3101eeca24191e129c4202fd53de8160c350ce69` | fix(fixtures): qualify control policy scopes |
| `1064966187340479ebb60a95ecafb4fcbb7c9ddc` | `8e388b6f78619d3679fc14f445bc2267673e1a1e` | `4a5e9e9af382219e709f24173c2f299317089058` | `c06c95e620ca972c2624165620066e5e30bd88ac` | fix(fixtures): bound control constructor aliases |
| `f411681e19f03c5d386799d92bb1473ba98d1a01` | `1064966187340479ebb60a95ecafb4fcbb7c9ddc` | `0ec820649f2338e628a271c1434b34ec5a8d3121` | `cac05549f582588ebd4e0747ba469e2577b3f399` | fix(fixtures): bind historical NUL allowances to ancestry |
| `69d3ac3169e1e8dfb810099a384c227e21b59e0d` | `f411681e19f03c5d386799d92bb1473ba98d1a01` | `9c606664821214be2b63501bdaa0d20c1f935683` | `e736c84e9b6c855478d59f563f1bfc94332f59b3` | fix(fixtures): reject aliased dynamic constructors |
| `a707f5af9612118d6d41450c5090e5c11c3e5c10` | `69d3ac3169e1e8dfb810099a384c227e21b59e0d` | `93ad8df0080d9b988b443daa55b54ac0b34c06b1` | `71bba397f22b648cebde9871d50156324c7680a5` | fix(fixtures): reject wildcard constructor imports |
| `fc33b1f461321f319b8c2566d9f0faf6c535b77b` | `a707f5af9612118d6d41450c5090e5c11c3e5c10` | `c0531f5f2a8feb76a81530d77e1fbdc3733f3364` | `e11b0a89eadcaf13a702216751e60785c0364223` | fix(fixtures): add hardened aggregate predecessor authority |
| `a88dd1233c01f780544d563b2a030fdd1cfd0c0f` | `fc33b1f461321f319b8c2566d9f0faf6c535b77b` | `eaf3def9a0a66f8d67c51f5122f78b194d400b99` | `e0adb38fc03251d45a7b7f88ee8e25bc31315f8d` | fix(fixtures): adopt hardened authority objects |

- Semantic delta: `Δ(f43e4159ba98f51ab68075b08c4e56db2dafb6ac, 94b0dd97247093f5ca3eb5dee4f1e3c6926e6439)`.
- Parent tree: `b309781f20fbeff648a72ea88107525ab5ccf0ad`.
- Child tree: `5c62360551b4b396f242d70e94e9773ac770554c`.
- Stable patch ID: `6a879cb252104eec1e54b8d25396a5895d8c39ff`.

Delta paths:

- `scripts/test_fixture_registry_authority.py`

Evidence to preserve:

- `authority tests 53/53 normal`
- `authority tests 53/53 optimized`
- `aggregate validator tests 48/48 normal`
- `aggregate validator tests 48/48 optimized`
- `CLI parity passed`
- `strict fsck passed`
- `evidence-only commits were not ancestors`

### 6. Apple benchmark range

- Exact inclusive range: `1f5c2f5282b1be0fdbac508749e99b5e790d3a9b^..8be4f513286813a7a1cbe7bbc997f53b7d557209`. Only this full canonical range is executable; abbreviated range references are rejected.
- Count: `12`; merge commits: `0`.
- Cumulative stable patch ID: `90979b638eda243ca0269dceadb34c32e8bc6fd4`.
- Path count: `10`.

Owned paths:

- `benchmarks/apple/.gitignore`
- `benchmarks/apple/Package.swift`
- `benchmarks/apple/README.md`
- `benchmarks/apple/Sources/AppleBenchmarkHarness/MockWorkloads.swift`
- `benchmarks/apple/Sources/AppleBenchmarkHarness/Models.swift`
- `benchmarks/apple/Sources/AppleBenchmarkHarness/Resources/workload.json`
- `benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift`
- `benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift`
- `benchmarks/apple/Sources/apple-benchmark/main.swift`
- `benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift`

Source ledger:

| Commit | Parent(s) | Tree | Stable patch ID | Subject |
|---|---|---|---|---|
| `1f5c2f5282b1be0fdbac508749e99b5e790d3a9b` | `abfe3fca3767fbfce724beb3ecde2ceb65f676ef` | `46ae7dfad21feead9f34690fbe25d2178488bef0` | `8c86db305115e827e0cb112162e06154db88aa77` | feat(benchmarks): scaffold offline Apple release harness |
| `ece70592c9b6c5cef4dcf9e84c0ab90981f37010` | `1f5c2f5282b1be0fdbac508749e99b5e790d3a9b` | `c9705ef55ca141aa05d99e5303034e6e6800062f` | `e672d06b5033b1d57859f4e993ba2d025cabd917` | fix(benchmarks): enforce actual Apple release configuration |
| `9ef7a1f081adce25770579d151a49cab52666971` | `ece70592c9b6c5cef4dcf9e84c0ab90981f37010` | `e3f5ee81fd3a69cadc2f6fccc262fb2533dc563e` | `6aed74c9c5530267deab6eec1634856c385fff7f` | fix(benchmarks): pin artifact identities |
| `8689d7a8e010631839a39cb0415c135a604f8df3` | `9ef7a1f081adce25770579d151a49cab52666971` | `983e8fef7ba2596f022f42b74f4480f0851f8ed2` | `1773776d12ed4f1120ff4df60c35a876c9607fb1` | fix(benchmarks): bind runner to reviewed fixture |
| `dc91b01d68fa05a298f82233aa26d33050c10e99` | `8689d7a8e010631839a39cb0415c135a604f8df3` | `b87e66277b70d8bf9a86dd5867ef5e76077482ce` | `b95da1d05d00d3af316ac2ea9343121ff4671603` | fix(benchmarks): require distinct trace output |
| `5abf24f3486ef355b1c8fa0474f9a75f842f7a0e` | `dc91b01d68fa05a298f82233aa26d33050c10e99` | `d38bb3bd9c10eea23dbfb493108c1ef31eebebf9` | `792e51b8204251dbca4d08f1ce32934718c448ad` | fix(benchmarks): bound evidence decoding |
| `1f97f64e5b94e10f762233e5743e493645a12470` | `5abf24f3486ef355b1c8fa0474f9a75f842f7a0e` | `fa0c491b7c41c2740a33ad7aed14a56d1999d7e0` | `7b4bc7cc93b96c4bef86e409a3b8347b52ed1ce9` | fix(benchmarks): enforce evidence provenance |
| `e965a45b72e6991c84953f4227f81aea3d3df977` | `1f97f64e5b94e10f762233e5743e493645a12470` | `ed4601fb570aa62985480cb30321535774ebc517` | `72ad2754dcbe74708106004b5cf3f249f7131a82` | fix(benchmarks): preserve evidence budgets |
| `b0980a21050f91a9f1cc6b721713424a8957be2a` | `e965a45b72e6991c84953f4227f81aea3d3df977` | `ee3974e766c60b30c2463f478e6c77b98139cc6a` | `2edb541ae175357275480815585be2e1e57b61bd` | style(benchmarks): apply xcode swift-format |
| `4c5b6aa927b5b9ba339fdd81e5f38257a2fa1100` | `b0980a21050f91a9f1cc6b721713424a8957be2a` | `8fcc84d576e8a3b4c84bd2841105335971511b69` | `73ecfde3a181f0016998c3c013b05f3ebc891def` | test(benchmarks): exercise artifact provenance |
| `44df9e8d352f148b91002dfcc89927248c0b145d` | `4c5b6aa927b5b9ba339fdd81e5f38257a2fa1100` | `98adb52fd3bd754c17a49904ea716cc9c7f0d71f` | `d213a5dc69858a206e9978186eb1baa7e131be0f` | fix(benchmarks): cap fixture input size |
| `8be4f513286813a7a1cbe7bbc997f53b7d557209` | `44df9e8d352f148b91002dfcc89927248c0b145d` | `486c5862adb0df986c46c0d529d43b91710457dc` | `1f2689250cbc9f5a35a2d630b9f47fb16a19bcf8` | docs(benchmarks): document evidence trust boundaries |

### 7. Proxy and deployment proof

- Exact inclusive range: `1ffc341888ea6f22bbaad42b5f989038213d72d4^..e3a2d2e662f2e606f318d35f4fccc63ba9738f7c`. Only this full canonical range is executable; abbreviated range references are rejected.
- Count: `40`; merge commits: `0`.
- Cumulative stable patch ID: `2897a3eca65b0dee5640c5e8cc04ae19916073f6`.
- Path count: `10`.

Owned paths:

- `docs/deployment/README.md`
- `scripts/README.md`
- `scripts/caddy_proof.py`
- `scripts/test_caddy_proof.py`
- `scripts/test_traefik_proof.py`
- `scripts/traefik_proof.py`
- `tests/integration/hermes-caddy/README.md`
- `tests/integration/hermes-traefik/README.md`
- `tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt`
- `tests/integration/hermes-traefik/traefik-proof-evidence.json`

Source ledger:

| Commit | Parent(s) | Tree | Stable patch ID | Subject |
|---|---|---|---|---|
| `1ffc341888ea6f22bbaad42b5f989038213d72d4` | `abfe3fca3767fbfce724beb3ecde2ceb65f676ef` | `95bf37e25c5e066f263e047cb99a60f4bc09edf9` | `6b6d7f43bd06fe60763e19ea7226d254b124b97d` | fix(traefik): complete synthetic deployment proof |
| `9ea133c7caf87d55e5db31b7c7ec44e503cbf3cc` | `1ffc341888ea6f22bbaad42b5f989038213d72d4` | `324f8f0b5a80cecb18a415fe32e9195f2b1aa6da` | `a62154d9fd66aca00df571ea887db236f37e9f4b` | fix(traefik): preserve PTY TTL boundary |
| `38077ec4a9234dcaee19569ffae76b998f28602a` | `9ea133c7caf87d55e5db31b7c7ec44e503cbf3cc` | `c288cba869c9bca1aa36663bdeff99fe2353b5a5` | `f5db0ed31e88563ad1121c84d11a21cf811a9e01` | fix(traefik): enforce PTY reattach TTL |
| `9b11ffb1b6631de3258c66e032fdde429b96974d` | `38077ec4a9234dcaee19569ffae76b998f28602a` | `6413ad4a1ced36166a96362b5901e14d522e299b` | `854f37c7f92867976008f53004686085d40ef489` | fix(traefik): harden PTY lifecycle timestamps |
| `93c5f2b098fcc08a19a6aace78e935932f9e77c3` | `9b11ffb1b6631de3258c66e032fdde429b96974d` | `0e6e402f6ecbc197ff73f8458bfad4b087daa0ce` | `9b70e6703d7d9d70acafa398592fc76b8486b4c7` | fix(traefik): close PTY lifecycle and evidence gaps |
| `b8adb021cad578adad224d798df2c033da73b6f8` | `93c5f2b098fcc08a19a6aace78e935932f9e77c3` | `2e19bd7579e57bdbc1594a182ecf9de2e061db28` | `c64d9e96cdfca933a2098903847101653eca1d58` | fix(traefik): align wrong-host denial with adapter |
| `bab866fa4b2df767af624f564ffa226e547fb922` | `b8adb021cad578adad224d798df2c033da73b6f8` | `b157106959500970ffdff936174840ad1eed5c75` | `81069b99b48aee066571b07f3a1626fdcdf53966` | fix(traefik): validate forwarded authority syntax |
| `7b2b19e954ce3eeb1f532e1f7b787cbd9af5b1f6` | `bab866fa4b2df767af624f564ffa226e547fb922` | `ba36fc09a68267e3bb26be802040e80e02b0a8a4` | `9962cdd9f44248dbc975901034e625e29f850dec` | fix(traefik): close strict authority parser gaps |
| `c6d502a11d21db2c92d2b6b2aa7fd7a1c9c837a8` | `7b2b19e954ce3eeb1f532e1f7b787cbd9af5b1f6` | `37998c2c367a12767bd07bf28efb79ecb257b2a7` | `91521da57d4dd2422494d203beec9d1302640c69` | chore(traefik): bind evidence to parser sources |
| `7e39f191d47d49cab5a6d991d241c1db16d219f3` | `c6d502a11d21db2c92d2b6b2aa7fd7a1c9c837a8` | `31d6af0659b7fa964d2ba0a7bcd9f2779659817a` | `39dc17eea8e0608c7c40279b85cdc33439dcdd12` | fix(traefik): bind parser evidence and header grammar |
| `0c6147ebd5d74feb07d1bb55f4b182dd72c4fb81` | `7e39f191d47d49cab5a6d991d241c1db16d219f3` | `79b8473bb0d16dc628d9316e925b7bc7fa107ca0` | `4c21651b3f826f533915e1c4b5e434d28cf2f2f9` | chore(traefik): refresh parser-bound evidence |
| `48feae9a06346f7c80adf0a0fe957d9c0c010776` | `0c6147ebd5d74feb07d1bb55f4b182dd72c4fb81` | `5c3efaa3300e00792fd8fb32bec3e37e336fa111` | `beb34cd4aa5bf3696552ad205c07d979e61695f7` | fix(traefik): stabilize parser provenance ancestry |
| `f5e47d557cf62e639e2bcdcdd449feb25b920b58` | `48feae9a06346f7c80adf0a0fe957d9c0c010776` | `028cf56e0b2c0b526bbaf5b974c60434a5b13555` | `6c4d085a7e10e6d9aca42e488d6ce03c6bfd694d` | chore(traefik): refresh stable provenance evidence |
| `237c8209274b92461ed0e37d97db96692c85eb6b` | `f5e47d557cf62e639e2bcdcdd449feb25b920b58` | `6f7be90c699f6a6e35e73bcf144085ba24d7c4e0` | `b333547ac7d2bc23ad36dbf0f66872b2c650bb6b` | fix(traefik): make parser source ancestry deterministic |
| `c5c330639249e6b12032aa2f315205f7eb345638` | `237c8209274b92461ed0e37d97db96692c85eb6b` | `2fa0e2dfee3e0c3ae6bd96860e6c467fd7b7f20f` | `e8e658a6d5e0a8319badb1b6da9dde708b9914b3` | fix(traefik): bound parser provenance traversal |
| `db8d7050453643f6ea7f3b2f974cfded1d7a2ee7` | `c5c330639249e6b12032aa2f315205f7eb345638` | `1a2129de86f127116651c12d747db27f78cde814` | `a8a2175a5611392fa878283162e9349ff6fd4e12` | fix(traefik): validate repository object formats |
| `fbc746592267fc31ada58f4810f43e2210dfb4a9` | `db8d7050453643f6ea7f3b2f974cfded1d7a2ee7` | `13b9baaa63ce3853842fd89f2adf7a8b6a2096fe` | `e29278ec1db7173107aadd1d1c338a7d551b118f` | fix(traefik): harden parser provenance topology |
| `4834affd8d4400723366a331305d143481d447ac` | `fbc746592267fc31ada58f4810f43e2210dfb4a9` | `ee299eb7a8518313a853cb2a37277f2dc28205ef` | `d80488b6784f63cf22df3c1b1531943b7700d452` | test(traefik): pin retained provenance contract |
| `5cebf66cedcc5ab49327d17cd911f4c1353a1068` | `4834affd8d4400723366a331305d143481d447ac` | `b6b4b02bc093eb6140bc334d62ac11dc9ac59461` | `bdf96658ea7626c8f9b98bfedafedbb6ef793812` | fix(traefik): close provenance topology races |
| `b67233f7b6ec00ef0d756acfc402055314d06422` | `5cebf66cedcc5ab49327d17cd911f4c1353a1068` | `d654f3da44f4e8c702708203c793911a5394aadb` | `bd268a07b1e915f616a9b237a260da3c89a1ea68` | fix(traefik): bind provenance metadata to trusted root |
| `4d9f8dc218e9acfba330b34c84cccb76d5730e28` | `b67233f7b6ec00ef0d756acfc402055314d06422` | `ac321023238c6271c9e323269254ff44a7053717` | `449fc7532e169556a2d4835eadff43922bd713d6` | fix(traefik): pin metadata identities during provenance |
| `5201ad8a2eb520e6170f84d9539dcf0cee45276e` | `4d9f8dc218e9acfba330b34c84cccb76d5730e28` | `d2489914226288abb313bbefed414f7b2ffd7f82` | `af0daf5051ed67fdc4fb763625c5486d0fccf07b` | fix(traefik): fence static and initial Git traversal |
| `f4a8776b677b615bc22a8cd92c898d005e37301a` | `5201ad8a2eb520e6170f84d9539dcf0cee45276e` | `68eb5367e69745c98116a08b4900c052ad89590e` | `26d1e7ff726e06ee5aea6a74d6280a13464f0b92` | fix(traefik): pin HEAD refs before provenance Git |
| `222ec79c0f5958c388f1c60f484b5506f36d972b` | `f4a8776b677b615bc22a8cd92c898d005e37301a` | `a4379af320504f3045ce933388debf07e14c3604` | `86cba5751d97806c91357b96c73249166c99ea1e` | fix(traefik): anchor linked worktrees to retained root |
| `28a2e82e2941716c6e0fb6bd3895ae1bf3871743` | `222ec79c0f5958c388f1c60f484b5506f36d972b` | `9efd38c415cfc680146d8577723d8e0c6015eea6` | `71b1d50c10da409dfa7e59b8f50c11df7e590158` | fix(traefik): fence chained symbolic refs |
| `43a84457339b1038e8832a9fc406c02e380ac6d8` | `28a2e82e2941716c6e0fb6bd3895ae1bf3871743` | `790f4d731386e2e16df115c20991a98f15dd52bf` | `47c110d0867805da63952c6d4d8ce6f64a26c0a3` | fix(caddy): derive browser evidence provenance |
| `e87207f81b24d6b86cba649ca66ffbb5c5c0d0a0` | `43a84457339b1038e8832a9fc406c02e380ac6d8` | `f9bc90ce6db86ed9f91cd49bae3219b35a6141c5` | `60a12cb96aa3e95d9df7a19ad38c0e8dace3b4a1` | docs(deployment): clarify browser evidence trust |
| `5a38561c0ec62466775782b541733b013894c801` | `e87207f81b24d6b86cba649ca66ffbb5c5c0d0a0` | `88aa9bd56a9cec1b10795b70847b6e636fd7f9a6` | `bbeb1cce62db1601f151225f9b0bfc3c7e921e24` | fix(caddy): reject untrusted browser pass claims |
| `decf110d9678ec38ad033dd324c43aef084ad247` | `5a38561c0ec62466775782b541733b013894c801` | `8fd0aee1861eab3261f7d5ad8283b5e0aaad938e` | `518772d2195828f7e7225cff5a95480bf2d7c260` | fix(caddy): fail closed on browser execution forgeries |
| `892ce8b83a4f52b49c49df4760729cfdcba1f61a` | `decf110d9678ec38ad033dd324c43aef084ad247` | `1abb0a48422431c38cb3e4afcb6678da13ddc0d8` | `c4f020e6abeb058b729ea9cf460cc493336e6614` | test(caddy): cover residual proof trust boundaries |
| `1c939ddd36a613b1d45c1265c45e3ff7b6e01c13` | `892ce8b83a4f52b49c49df4760729cfdcba1f61a` | `468f68c4fcbf9188c7641eafec5db16a5ce6bb2f` | `f1ba073a2744f711f87e5d5d69ed95dade8b5841` | docs(caddy): clarify task-265 residual trust boundaries |
| `ffffc3f82974ea6d9c5b4123b2ebefe5976b4379` | `1c939ddd36a613b1d45c1265c45e3ff7b6e01c13` | `5dd029807012bc7d26f52205eef97aaf168b736f` | `375ab79ed01646b3fd95b67ffa194b21346e94e5` | fix(caddy): close residual proof trust gaps |
| `5fa115b8fa5a359240b34408fcc4955caa516074` | `ffffc3f82974ea6d9c5b4123b2ebefe5976b4379` | `50ee7ad25f05b8fd4c66f1791b194f3e8d75c310` | `736cec3bf7059f55e1bcdb96ad0665e3d99e77fb` | fix(caddy): close Git and static deadline residuals |
| `1b807548eac7b4b5ba017f1e637149b380e242df` | `5fa115b8fa5a359240b34408fcc4955caa516074` | `0ecee2249a377a4599c812d5bddb7d44f5e0ea77` | `b9d942eb5c94998676351960435694279a0080e3` | fix(caddy): close residual trust boundaries |
| `215f4bcd1eb66a883fd97b9c3048dd3f97e19ef1` | `1b807548eac7b4b5ba017f1e637149b380e242df` | `c74d955f8e892624283433f3ac7a74296218d93f` | `a795fe6af9078dba16772bf147d2e7354a48a1ab` | fix(caddy-proof): pin Git metadata across commands |
| `8c7f162ef9ca470db2142dc896a23f188bbf0770` | `215f4bcd1eb66a883fd97b9c3048dd3f97e19ef1` | `9304d895bba7601f9ffa6f3c690fb573f7a7558d` | `706bf25779c5b6f09120af4955130497df13da75` | fix(caddy-proof): bind recursive Git trust surface |
| `1a6a97281c79a357ac13d5cf4ace678efa52b4b2` | `8c7f162ef9ca470db2142dc896a23f188bbf0770` | `bf850d5559d1e218174e020d4ae3c29d5a55b5e8` | `a471456eac3643e62330fd04af1f6f8f0e67f381` | fix(caddy-proof): bound metadata link scan descriptors |
| `272fd31300d1563f411b2b4b1f37a605a6127b1a` | `1a6a97281c79a357ac13d5cf4ace678efa52b4b2` | `5a0662edb18a4f0c4985aff1ccb4307bc85b0f84` | `4783e4fff0dd27b23006b9b381ec9664278b9c29` | fix(caddy-proof): bound Git provenance deadline |
| `c88cb2f4e5eecf20b7df1e3124579563f2137ec0` | `272fd31300d1563f411b2b4b1f37a605a6127b1a` | `2f071824439b4e37ab1d52937693059527b9c8ac` | `aa0ffa00e981c488dfdc865d4d4f261ea71be1d0` | fix(caddy-proof): reject loose replacement refs |
| `e3a2d2e662f2e606f318d35f4fccc63ba9738f7c` | `c88cb2f4e5eecf20b7df1e3124579563f2137ec0` | `2c0bf65970fa7368557fabf803e226894b6d4574` | `8236827fbaef9e9548830634879b29f4c16915e7` | fix(caddy-proof): share metadata content budget |

### 8. Launcher semantic projection replacing marker placeholder

Source commit `d3c40687659ee645a5f03bc80cbf61ec8c49979a`; parent(s) `3765e8ddcaf44542083dab323375ae16615cd40d`; tree `5e8c66d584219a8599fbe61b3c5f83dce297034e`; stable patch ID `14b9080de801d7e88c09522076f78ff62ca8eca8`.

Ancestry audit only: `92891b8b6fdd28c54e32684e4bd5cb242940cac8^..d3c40687659ee645a5f03bc80cbf61ec8c49979a` has `25` commits and `0` merge commits. Do not replay this ancestry as a raw branch.

| Commit | Parent(s) | Tree | Stable patch ID | Subject |
|---|---|---|---|---|
| `92891b8b6fdd28c54e32684e4bd5cb242940cac8` | `abfe3fca3767fbfce724beb3ecde2ceb65f676ef` | `3c8b096a159b49d99e82db8ee3acf53e23ac6e77` | `764d0a6730d23b154efafeb46692143ce4101683` | feat(fixtures): add strict live run marker |
| `8e0fb89060eac1eed20316ff60663ae969bcdb18` | `92891b8b6fdd28c54e32684e4bd5cb242940cac8` | `991879b69b22f5b0bdf2023e576541869c550c76` | `d63c069dc40f8250f0f30a99bb07389225df6c25` | feat(fixtures): bind launcher lifecycle to run markers |
| `927cfebb9f5f2e789e7cee2d7e6d84e78960a8fd` | `8e0fb89060eac1eed20316ff60663ae969bcdb18` | `dcd9ac4269e0a2659253e8dc08abb0180e70f84a` | `bdea623c7d0d3003b14a538f6a373229b1909846` | fix(fixtures): gate live handoff on exact marker |
| `ce8ab0812d817ac15485f885b0e9c9214083235f` | `927cfebb9f5f2e789e7cee2d7e6d84e78960a8fd` | `72d605696831fcb0e2b6bd310e42e5ebb837aaa0` | `cf1ae92453868ad666d50b5f7da51ef6d54da581` | fix(fixtures): reject duplicate batch markers |
| `53f4752b1c2a76f9c1e87bb182c49f1bfd1e92a9` | `ce8ab0812d817ac15485f885b0e9c9214083235f` | `1bbcd3e2c51f0572b9c39ff34dba6531b14db17f` | `146e9832f4a8a045b63b23eb9d145c4babd84d7d` | fix(fixtures): close marker schema path failures |
| `942153e74842ff9a70dd4ce1673e7d87692c6dcd` | `53f4752b1c2a76f9c1e87bb182c49f1bfd1e92a9` | `edba3074dcfec7c5b0da788f39db76f6bf28c4f8` | `42cb1f2aae61a82b75442da9bd53b616bf890be1` | fix(fixtures): pin post-run ownership cleanup |
| `293dbca7f4e992d16e848acb73dd29257ed4ad0d` | `942153e74842ff9a70dd4ce1673e7d87692c6dcd` | `fcce71993b6bb775926af956a5218832f349cb18` | `6bed88e81afda3e08ff8045ea6055fd45fd8f641` | fix(fixtures): harden live run marker transactions |
| `44cc58146569bc580d9fd3f78b9241102df62c97` | `293dbca7f4e992d16e848acb73dd29257ed4ad0d` | `7a1ed34a609e7d2ff39a5bc93d5ce3d2e7f5e3e5` | `aef952124c1ebd8ee1c665f33bdf25b1ce287da1` | fix(fixtures): harden marker publication and proof handoff |
| `f669d389251370e5e8e4503f6cca8a91b1c3344f` | `44cc58146569bc580d9fd3f78b9241102df62c97` | `6792d32b24423b4de6d950608323ea8f3c968836` | `b3309b0b532920135995dfacb3d43f7a0a31d0f5` | fix(fixtures): fence lifecycle records by generation |
| `1a1a7b6d092869d54a992e43e8762678d62dda07` | `f669d389251370e5e8e4503f6cca8a91b1c3344f` | `ba03817b6c8a48a9e43c0925e74025b8272c178b` | `7991af0e633bfcda66a656622820d2f986446fd7` | fix(fixtures): bound marker handoff parser inputs |
| `71555c552f536559d3c6bd04c1f9ac2e0f2ea8f1` | `1a1a7b6d092869d54a992e43e8762678d62dda07` | `7b520036db0814c1743077a89b4a0a22fb4ad1d1` | `41b9cdfafe883d3cec04b0b8c26edc881c6f5524` | fix(fixtures): harden launcher result and marker schemas |
| `ea2d878975264bce7a2f138b1827175e9135df11` | `71555c552f536559d3c6bd04c1f9ac2e0f2ea8f1` | `44aae3ef41ea929db344243d19ffe76c70985944` | `3a3a4a81a257083e92f73b52f416b6274d5b1873` | fix(fixtures): derive exact launcher result envelope |
| `a9490e4be8d98f268cb8876d0cf4a47daa2453d0` | `ea2d878975264bce7a2f138b1827175e9135df11` | `05731f6cbb11504680578d952f11371b81903293` | `ff21b37fa92473c7194dd69901eaab6c97420e64` | fix(fixtures): restore canonical live handoff framing |
| `2930ec9acd33eee4d5678aef65eed012ba1a6a99` | `a9490e4be8d98f268cb8876d0cf4a47daa2453d0` | `3d42b25860c152a4e0b77221f89fc4b35fcdd029` | `2c0a604510076ca85e6013cc8ee4a23d853d5ca6` | fix(fixtures): correct skill live handoff CLI |
| `47e6152ff1cb4dfaa8a2732b42d733defc67d126` | `2930ec9acd33eee4d5678aef65eed012ba1a6a99` | `21a6ed318528f583559d908797ba0473b8ff5a20` | `8050e11faa82e3633cb4d7ace3634508844d0a93` | fix(launcher): fail closed before marker handoff |
| `342664494ad5048335b277e8323ea2647955627b` | `47e6152ff1cb4dfaa8a2732b42d733defc67d126` | `74988e8e01ae119e3f4321d68f40aaade3ffc6a7` | `ef1c42ebbfccf461c1712c209b545af7b4765484` | fix(launcher): reject unsafe ancestors and split batches |
| `408a4d96c0e7cc9ae0e31532f317c8e7025e77ce` | `342664494ad5048335b277e8323ea2647955627b` | `31a59fc0c2ee5c766227bb8fd5cd9468d77dcdb4` | `5ccd8478b76b211476768c5ed5cc2acbf9e45ab7` | fix(launcher): harden canonical data-root handoff |
| `1139665710ff15dc64a3ca5bedf799e614d76b8f` | `408a4d96c0e7cc9ae0e31532f317c8e7025e77ce` | `2d9cbb08485caec8f185e445008643af0cf7aa6d` | `e72ae748c915a72136860cddc7169450ef1070ef` | fix(launcher): bind handoff to persisted data identity |
| `6c6614c8d953112603bfcc1e3f6c74a7e7549183` | `1139665710ff15dc64a3ca5bedf799e614d76b8f` | `a4646f3353ef113dbcfc4d17dea1425fbcc6014c` | `6df9d37db7dc2416a22e2cf0abad4213f621c45c` | fix(launcher): fence live-run publication boundaries |
| `4ecfb409593add54fa10b926d8c62c90f2a9b201` | `6c6614c8d953112603bfcc1e3f6c74a7e7549183` | `7455b9db20558f01230d896a3cea4d6fd9292d5a` | `d1f97056b1076b22d61458a0287c9bf3f362c0be` | fix(launcher): bind cidfiles to detached-run witnesses |
| `8cac6e3714caefd01ed4671f250b916737e31893` | `4ecfb409593add54fa10b926d8c62c90f2a9b201` | `5688dca67fc61156a0380d843044db323134038f` | `aeaaf3f0a6363a55d655ccce65b7020bd6c70426` | fix(launcher): bind identity to engine invocation witness |
| `7df3684966a4b5f2aaeda11953da01f9074884a3` | `8cac6e3714caefd01ed4671f250b916737e31893` | `9678562449e2d48151b698d40398754f255f7c15` | `9d57402b1176a945c1a8f28ead689824386d768d` | fix(launcher): require trusted detached-run receipts |
| `ffadba4636d458ca380a9f5cb210d4cf6a6c26a2` | `7df3684966a4b5f2aaeda11953da01f9074884a3` | `b2a89d1499dea50ecbf00dd5a0e426ab11510117` | `5e4b3e0bc29d3783e6eaa7daff4da5d6937a4cc3` | fix(launcher): bind receipts to exact adapter objects |
| `3765e8ddcaf44542083dab323375ae16615cd40d` | `ffadba4636d458ca380a9f5cb210d4cf6a6c26a2` | `13d90e242445d0bbabffc67281da65fe64b44f9e` | `e35577fdad344bfcc734abf4864844d01ca01bfc` | fix(fixtures): harden one-shot live run authorization |
| `d3c40687659ee645a5f03bc80cbf61ec8c49979a` | `3765e8ddcaf44542083dab323375ae16615cd40d` | `5e8c66d584219a8599fbe61b3c5f83dce297034e` | `14b9080de801d7e88c09522076f78ff62ca8eca8` | fix(fixtures): bind receipt authority to one result |

Exact semantic projection paths:

- `.agents/skills/deploy-hermes-agent/SKILL.md`
- `apps/web/tests/live/README.md`
- `scripts/README.md`
- `scripts/hermes_agent.py`
- `scripts/live_run_marker.py`
- `scripts/read_launcher_result.py`
- `scripts/test_hermes_agent.py`
- `scripts/test_live_run_marker.py`
- `scripts/test_read_launcher_result.py`
- `scripts/test_with_live_credential.py`
- `scripts/with_live_credential.py`

Non-README mechanical paths: `10`. Excluded: `scripts/README.md`.

Exact old-blob preconditions:

| Path | Blob required before lane |
|---|---|
| `.agents/skills/deploy-hermes-agent/SKILL.md` | `ada5108dd0412adb07765d17693b19ba3e216754` |
| `apps/web/tests/live/README.md` | `a0eecc2a1fba0f427887f3d71497427aff0705e6` |
| `scripts/README.md` | `c2a31b8b58237551b698c64671a027da28ed84ff` |
| `scripts/hermes_agent.py` | `8f7240be5b8abe109e0492f5d927ceb9e186805e` |
| `scripts/live_run_marker.py` | `(absent)` |
| `scripts/read_launcher_result.py` | `c63ddcc2b17a020ec3313b3669eff0b1ad929dfc` |
| `scripts/test_hermes_agent.py` | `7ae790c748d6e319e5f4dc912d61bda93ef3e187` |
| `scripts/test_live_run_marker.py` | `(absent)` |
| `scripts/test_read_launcher_result.py` | `2c30f0fbd0fc50ccf9c05694920d6d2b74ecfed7` |
| `scripts/test_with_live_credential.py` | `e70b986720be98a66582e8550dc93e4564a52884` |
| `scripts/with_live_credential.py` | `b9e2c0ab1d80781fff681931fefc86e9e66efdf3` |

Approved scoped stable patch ID: `0030c185191be447cf53a54cc535c3a0ee172823`.
Approved scoped raw SHA-256: `abf56c277f205c229951bb6165afecb476cce08b5560872455a6d65d72b1b238`.

Do not replay the 25-commit marker ancestry. Materialize exact d3 blobs only.

### 9. Dependency audit correction

Source commit `a2a8a0b03f515409a02e6668d2600e5ebb6e5152`; parent(s) `4faf9497806b6551fe6d44d68b5f9a0bc7208ee3`; tree `cd109fbe707aaa7d566ae9c459fc6919eab9c0a5`; stable patch ID `774d81a80311b79e08bc258e0d7f665f46c25ad1`.

Owned paths:

- `docs/security/dependency-audit.md`
- `scripts/dependency_audit.py`
- `scripts/test_dependency_audit.py`

Rejected sources:

- `03e2b0c828276044d1229c0200a5ac969140a344`

### 10. Swift parity correction

- Semantic delta: `Δ(221620c04bb051f2597c52bdeb16ccc55c5b2e9c, 027806c8596f8b9a4ce200b2fe1344e013f46685)`.
- Parent tree: `f23d4063237404f445fb2705d679294598e2ed25`.
- Child tree: `3eb8b306179a2d05754f0c27feea35db6c48fdab`.
- Stable patch ID: `7cdebef1987d84539ed14fa026ee3c0dc0c6bbb5`.

Delta paths:

- `contracts/swift-parity/README.md`
- `contracts/swift-parity/Tests/HermternalSwiftParityTests/ParityTests.swift`

Reviewed ownership set:

- `contracts/swift-parity/README.md`
- `contracts/swift-parity/Sources/HermternalSwiftParity/Parity.swift`
- `contracts/swift-parity/Tests/HermternalSwiftParityTests/ParityTests.swift`

Source commit `221620c04bb051f2597c52bdeb16ccc55c5b2e9c`; parent(s) `482bac2d9e08d171a2a200b130f26789f3519ad2`; tree `f23d4063237404f445fb2705d679294598e2ed25`; stable patch ID `a60392f778356e46138b8ba9bde3266d259a3e3a`.

Required checks:

- `production Parity.swift blob unchanged`
- `validator blob unchanged`
- `debug suite 24/24`
- `release suite 24/24`
- `accept only c19_validator_timeout or c19_validator_blocked`
- `readyCaseCount=0`
- `liveClaim=false`
- `networkCalls=0`

### 11. Live-proof cumulative semantic projection replacing watermark placeholder

Source commit `80fe3b68fb676a3b6589fce9aed79140bf37b667`; parent(s) `f54c8511e67a50fa7a00bf28e694459c77cf21c3`; tree `29da48ddecab5bf8081ea24f62280d26b452baf2`; stable patch ID `ff53fcdd415825877de766e7d518a1cc7fe450d6`.

Ancestry audit only: `d3c40687659ee645a5f03bc80cbf61ec8c49979a^..80fe3b68fb676a3b6589fce9aed79140bf37b667` has `12` commits and `0` merge commits. Do not replay this ancestry as a raw branch.

| Commit | Parent(s) | Tree | Stable patch ID | Subject |
|---|---|---|---|---|
| `d3c40687659ee645a5f03bc80cbf61ec8c49979a` | `3765e8ddcaf44542083dab323375ae16615cd40d` | `5e8c66d584219a8599fbe61b3c5f83dce297034e` | `14b9080de801d7e88c09522076f78ff62ca8eca8` | fix(fixtures): bind receipt authority to one result |
| `a7f54b511fc52d0d8a6c59e2b42054cd8b13ece0` | `d3c40687659ee645a5f03bc80cbf61ec8c49979a` | `3525f63ed7eb8d72a243a980a03e02c1652cb8df` | `d7bb4fe90489268dd87e8bf407cac89904f4b757` | docs(live): reconcile approved proof contract documentation |
| `d9a79122376ac3c252867a954a557c7202bdc5a2` | `a7f54b511fc52d0d8a6c59e2b42054cd8b13ece0` | `eb02648aa090d5f28c4d8a188c013393812bf718` | `ceb44dfcfd5a31bfbf8567c847b49553e5023c1f` | fix(live): restore approved proof support surfaces |
| `c52acd09fc68af492985df33161d777fb2ae68a0` | `d9a79122376ac3c252867a954a557c7202bdc5a2` | `21ecf65546188a05eab00d877c60c21b3fac75a9` | `50f9b429aff2d944c71a7d04183579f44fdffd42` | fix(live): close history and credential boundaries |
| `f4317ca14580871bee16df91382a7fbe20ee7949` | `c52acd09fc68af492985df33161d777fb2ae68a0` | `4951a91eaf121d833c25eea5a3b3af3e5d521609` | `3ff60717e5069cd23cb068ce5c82981cef577bc7` | fix(live): harden proof executable and screenshot retention |
| `7ad8ef885b3e98bfe68a223184d48625cd7a7cca` | `f4317ca14580871bee16df91382a7fbe20ee7949` | `1cb2555e652d4e0a581e1f277c62254b4f02b998` | `0bea352cd608a72e989aab8882ebbd8b508b379b` | fix(live-proof): close security review gaps |
| `1c41bdcb909f7513a213b69aca2f7b2396b90f1c` | `7ad8ef885b3e98bfe68a223184d48625cd7a7cca` | `c9b673152bb31c997920be4c35e43e41ebb6126a` | `43d589cf037d27fc3606ef34fe52d53f8d38f4f1` | fix(live): harden screenshot Git provenance |
| `f7db616968284ae54a2c2f121398d2603b0ddc95` | `1c41bdcb909f7513a213b69aca2f7b2396b90f1c` | `49119cac82be923461a4f44bd4a29894342c97f8` | `955f10db9bc571662ba55a8cee1e87bfd8c1c60d` | fix(live): bind screenshot provenance evidence |
| `f0fddb509dd374bb63b5f10d186d6aaf1604379a` | `f7db616968284ae54a2c2f121398d2603b0ddc95` | `d4947d97dc74473a88c85dfb645f28292a219e9b` | `799d2ea086ed641d4722864f38c6e3f0aa169fba` | fix(live): close screenshot provenance publication gaps |
| `962d506b01550a90ca28b26da86f55c9f9563b09` | `f0fddb509dd374bb63b5f10d186d6aaf1604379a` | `0904d167458334e2d28bd45d6ccc49bae688ac70` | `38603efee0b7af9d353f8773fb7b301732c51670` | fix(live): support standard linked worktrees |
| `f54c8511e67a50fa7a00bf28e694459c77cf21c3` | `962d506b01550a90ca28b26da86f55c9f9563b09` | `62d7c4022c7140416befbe65fd87ecad691fd44d` | `a9cad2e91bf4845cb37c5d2bb4ccb70620c7fcff` | fix(live): harden Git config probe diagnostics |
| `80fe3b68fb676a3b6589fce9aed79140bf37b667` | `f54c8511e67a50fa7a00bf28e694459c77cf21c3` | `29da48ddecab5bf8081ea24f62280d26b452baf2` | `ff53fcdd415825877de766e7d518a1cc7fe450d6` | test(live): cover Git config probe fail-closed paths |

Required f54 checkpoint: `f54c8511e67a50fa7a00bf28e694459c77cf21c3`; parent `962d506b01550a90ca28b26da86f55c9f9563b09`; tree `62d7c4022c7140416befbe65fd87ecad691fd44d`; stable patch ID `a9cad2e91bf4845cb37c5d2bb4ccb70620c7fcff`.

Exact semantic projection paths:

- `apps/web/playwright.live.config.ts`
- `apps/web/src/lib/live-artifact-policy.test.ts`
- `apps/web/src/lib/live-screenshot-contract.test.ts`
- `apps/web/tests/live/README.md`
- `apps/web/tests/live/live-artifact-policy.mjs`
- `apps/web/tests/live/live-playwright-config.mjs`
- `apps/web/tests/live/live-proof-ledger.mjs`
- `apps/web/tests/live/live-proof-page-bridge.mjs`
- `apps/web/tests/live/live-proof-parent-compat.mjs`
- `apps/web/tests/live/live-proof-status.mjs`
- `apps/web/tests/live/live-reconciliation-auth.mjs`
- `apps/web/tests/live/live-reconciliation-transport.mjs`
- `apps/web/tests/live/live-reconciliation.mjs`
- `apps/web/tests/live/live-screenshot-capture.mjs`
- `apps/web/tests/live/live-screenshot-contract.mjs`
- `apps/web/tests/live/live-support-parent-compat.mjs`
- `apps/web/tests/live/live-trusted-executables.mjs`
- `apps/web/tests/live/official-hermes.spec.ts`
- `apps/web/tests/live/reconcile-live-proof.spec.ts`
- `scripts/README.md`
- `scripts/test_with_live_credential.py`
- `scripts/with_live_credential.py`

Non-README mechanical paths: `21`. Excluded: `scripts/README.md`.

Required exact d3 blobs before stage two:

- `apps/web/tests/live/README.md`
- `scripts/test_with_live_credential.py`
- `scripts/with_live_credential.py`

Exact old-blob preconditions:

| Path | Blob required before lane |
|---|---|
| `apps/web/playwright.live.config.ts` | `3d8d2c01d5e67e7bde596a00f50f355c99c83f98` |
| `apps/web/src/lib/live-artifact-policy.test.ts` | `b197a04c4cc8dc52228ccdacaa661117ec2a9843` |
| `apps/web/src/lib/live-screenshot-contract.test.ts` | `7845f13ba56ca78622c47327c6953422528de0ad` |
| `apps/web/tests/live/README.md` | `ee661172f7aa7c2c861a27795d8d70f170b5e090` |
| `apps/web/tests/live/live-artifact-policy.mjs` | `e6d5191e8a2cfc03d66365caadb86dfdf7afae78` |
| `apps/web/tests/live/live-playwright-config.mjs` | `(absent)` |
| `apps/web/tests/live/live-proof-ledger.mjs` | `(absent)` |
| `apps/web/tests/live/live-proof-page-bridge.mjs` | `(absent)` |
| `apps/web/tests/live/live-proof-parent-compat.mjs` | `(absent)` |
| `apps/web/tests/live/live-proof-status.mjs` | `(absent)` |
| `apps/web/tests/live/live-reconciliation-auth.mjs` | `(absent)` |
| `apps/web/tests/live/live-reconciliation-transport.mjs` | `(absent)` |
| `apps/web/tests/live/live-reconciliation.mjs` | `(absent)` |
| `apps/web/tests/live/live-screenshot-capture.mjs` | `(absent)` |
| `apps/web/tests/live/live-screenshot-contract.mjs` | `8998659df76513ba7c7a7a0256dd90f37a98a0f8` |
| `apps/web/tests/live/live-support-parent-compat.mjs` | `(absent)` |
| `apps/web/tests/live/live-trusted-executables.mjs` | `(absent)` |
| `apps/web/tests/live/official-hermes.spec.ts` | `301da9df3be3d15ac66470e9c86324625aa7db9c` |
| `apps/web/tests/live/reconcile-live-proof.spec.ts` | `(absent)` |
| `scripts/test_with_live_credential.py` | `ce28f1d8607df3b195bf56f23ebff24d495261f5` |
| `scripts/with_live_credential.py` | `fc8a3bd80773cd27de4853dcf7f553de57cfc870` |

Approved scoped stable patch ID: `1e4799b4eaf505bd4b06e939608edabc6698fca6`.
Approved scoped raw SHA-256: `85a8a57fef533d9cb8a3907550a769b704ab2fb478647b16402a12ceb8558fa1`.

The ancestry audit has 12 commits and 25 full-diff paths; the approved semantic projection is exactly 22 paths.

## Exact live overlap and 29-path blob matrix

Launcher scope: `11` paths. Live-proof scope: `22` paths. Intersection: `4` paths. Union: `29` paths.
Non-README launcher mechanical set: `10` paths. Non-README live mechanical set: `21` paths.

Four overlap paths:

- `apps/web/tests/live/README.md`
- `scripts/README.md`
- `scripts/test_with_live_credential.py`
- `scripts/with_live_credential.py`

The three remaining launcher/live overlaps must hold exact d3 blobs before stage two:

- `apps/web/tests/live/README.md`
- `scripts/test_with_live_credential.py`
- `scripts/with_live_credential.py`

| Path | Stage | Base | Proxy | d3 | f54 | 80fe | Expected final |
|---|---|---|---|---|---|---|---|
| `.agents/skills/deploy-hermes-agent/SKILL.md` | `launcher` | `ada5108dd0412adb07765d17693b19ba3e216754` | `ada5108dd0412adb07765d17693b19ba3e216754` | `26278be3c8e5988b7ebec0099d964c9e12e4422d` | `26278be3c8e5988b7ebec0099d964c9e12e4422d` | `(absent)` | `26278be3c8e5988b7ebec0099d964c9e12e4422d` |
| `apps/web/playwright.live.config.ts` | `live` | `3d8d2c01d5e67e7bde596a00f50f355c99c83f98` | `3d8d2c01d5e67e7bde596a00f50f355c99c83f98` | `(absent)` | `5432d7f342e8a91bc0f6d706460b2717e73c374b` | `5432d7f342e8a91bc0f6d706460b2717e73c374b` | `5432d7f342e8a91bc0f6d706460b2717e73c374b` |
| `apps/web/src/lib/live-artifact-policy.test.ts` | `live` | `b197a04c4cc8dc52228ccdacaa661117ec2a9843` | `b197a04c4cc8dc52228ccdacaa661117ec2a9843` | `(absent)` | `b36e79310bfc0a3440f6cc63fcd17262ebd39d0b` | `b36e79310bfc0a3440f6cc63fcd17262ebd39d0b` | `b36e79310bfc0a3440f6cc63fcd17262ebd39d0b` |
| `apps/web/src/lib/live-screenshot-contract.test.ts` | `live` | `7845f13ba56ca78622c47327c6953422528de0ad` | `7845f13ba56ca78622c47327c6953422528de0ad` | `(absent)` | `5b35494e76cb27e7ba25771d7b611641ddda3cd3` | `cc93ba5cd0a6f272446f9e1038814a5b4e3e215b` | `cc93ba5cd0a6f272446f9e1038814a5b4e3e215b` |
| `apps/web/tests/live/README.md` | `launcher-then-live` | `a0eecc2a1fba0f427887f3d71497427aff0705e6` | `a0eecc2a1fba0f427887f3d71497427aff0705e6` | `ee661172f7aa7c2c861a27795d8d70f170b5e090` | `68318c561649d67e880bd87024bd3e90cc20afd7` | `68318c561649d67e880bd87024bd3e90cc20afd7` | `68318c561649d67e880bd87024bd3e90cc20afd7` |
| `apps/web/tests/live/live-artifact-policy.mjs` | `live` | `e6d5191e8a2cfc03d66365caadb86dfdf7afae78` | `e6d5191e8a2cfc03d66365caadb86dfdf7afae78` | `(absent)` | `8287833afbaa3ff9f43619023c3681e16e13e5b7` | `8287833afbaa3ff9f43619023c3681e16e13e5b7` | `8287833afbaa3ff9f43619023c3681e16e13e5b7` |
| `apps/web/tests/live/live-playwright-config.mjs` | `live` | `(absent)` | `(absent)` | `(absent)` | `ef510ab16c977f5fbcee951acf00acc0fa6d4aa0` | `ef510ab16c977f5fbcee951acf00acc0fa6d4aa0` | `ef510ab16c977f5fbcee951acf00acc0fa6d4aa0` |
| `apps/web/tests/live/live-proof-ledger.mjs` | `live` | `(absent)` | `(absent)` | `(absent)` | `9acc52a1b083e572e8b3d8b7d86bb40382aeab12` | `9acc52a1b083e572e8b3d8b7d86bb40382aeab12` | `9acc52a1b083e572e8b3d8b7d86bb40382aeab12` |
| `apps/web/tests/live/live-proof-page-bridge.mjs` | `live` | `(absent)` | `(absent)` | `(absent)` | `86416764864a50e06feca5685a877543bec9ddb6` | `86416764864a50e06feca5685a877543bec9ddb6` | `86416764864a50e06feca5685a877543bec9ddb6` |
| `apps/web/tests/live/live-proof-parent-compat.mjs` | `live` | `(absent)` | `(absent)` | `(absent)` | `095c1ebddfae33069f107c2e72a37a9d9917e751` | `095c1ebddfae33069f107c2e72a37a9d9917e751` | `095c1ebddfae33069f107c2e72a37a9d9917e751` |
| `apps/web/tests/live/live-proof-status.mjs` | `live` | `(absent)` | `(absent)` | `(absent)` | `2a18991dd417b2f848a99b6c17ae69171c56dcce` | `2a18991dd417b2f848a99b6c17ae69171c56dcce` | `2a18991dd417b2f848a99b6c17ae69171c56dcce` |
| `apps/web/tests/live/live-reconciliation-auth.mjs` | `live` | `(absent)` | `(absent)` | `(absent)` | `22f335ad5c6fc9070f8ec80b1856162031419b85` | `22f335ad5c6fc9070f8ec80b1856162031419b85` | `22f335ad5c6fc9070f8ec80b1856162031419b85` |
| `apps/web/tests/live/live-reconciliation-transport.mjs` | `live` | `(absent)` | `(absent)` | `(absent)` | `4fd60df27f94848b128389ace385a329a7979bc8` | `4fd60df27f94848b128389ace385a329a7979bc8` | `4fd60df27f94848b128389ace385a329a7979bc8` |
| `apps/web/tests/live/live-reconciliation.mjs` | `live` | `(absent)` | `(absent)` | `(absent)` | `bce322c9ced1a0820646b9b82e025f5f0a501225` | `bce322c9ced1a0820646b9b82e025f5f0a501225` | `bce322c9ced1a0820646b9b82e025f5f0a501225` |
| `apps/web/tests/live/live-screenshot-capture.mjs` | `live` | `(absent)` | `(absent)` | `(absent)` | `73ff205174fc8be449cf90cfef715a225b2a6b51` | `4cdd81a3ce8023e350654ecb241e5e55136cd342` | `4cdd81a3ce8023e350654ecb241e5e55136cd342` |
| `apps/web/tests/live/live-screenshot-contract.mjs` | `live` | `8998659df76513ba7c7a7a0256dd90f37a98a0f8` | `8998659df76513ba7c7a7a0256dd90f37a98a0f8` | `(absent)` | `e8ea316673e5603af3d8bb52e0c4a9f2ecb9d727` | `e8ea316673e5603af3d8bb52e0c4a9f2ecb9d727` | `e8ea316673e5603af3d8bb52e0c4a9f2ecb9d727` |
| `apps/web/tests/live/live-support-parent-compat.mjs` | `live` | `(absent)` | `(absent)` | `(absent)` | `cf51aa8a7f380190fa5ed299937e15c8c5f25430` | `cf51aa8a7f380190fa5ed299937e15c8c5f25430` | `cf51aa8a7f380190fa5ed299937e15c8c5f25430` |
| `apps/web/tests/live/live-trusted-executables.mjs` | `live` | `(absent)` | `(absent)` | `(absent)` | `aab154699a799a98de7c7bde0544ba51d3f3512c` | `aab154699a799a98de7c7bde0544ba51d3f3512c` | `aab154699a799a98de7c7bde0544ba51d3f3512c` |
| `apps/web/tests/live/official-hermes.spec.ts` | `live` | `301da9df3be3d15ac66470e9c86324625aa7db9c` | `301da9df3be3d15ac66470e9c86324625aa7db9c` | `(absent)` | `f8c738954f2685cca34709a1991dc03aa3e3c09e` | `f8c738954f2685cca34709a1991dc03aa3e3c09e` | `f8c738954f2685cca34709a1991dc03aa3e3c09e` |
| `apps/web/tests/live/reconcile-live-proof.spec.ts` | `live` | `(absent)` | `(absent)` | `(absent)` | `54c151422d581dd598ff8d8caeb2a38710b62069` | `54c151422d581dd598ff8d8caeb2a38710b62069` | `54c151422d581dd598ff8d8caeb2a38710b62069` |
| `scripts/README.md` | `reviewed-readme-merge` | `30c9ad5f02f48740c52f2f0ef4c1446f0cf06b6f` | `c2a31b8b58237551b698c64671a027da28ed84ff` | `9c8f7d63ed0aeb0ca62954c3ffc16c8b51f806fc` | `8994e46b6eea777126058ae37567d0f68a86426a` | `8994e46b6eea777126058ae37567d0f68a86426a` | `d74f0c1431901f83e736389395a122c48e521a32` |
| `scripts/hermes_agent.py` | `launcher` | `8f7240be5b8abe109e0492f5d927ceb9e186805e` | `8f7240be5b8abe109e0492f5d927ceb9e186805e` | `5d02bce73220917bc117a62e01be0c4a62bf0671` | `5d02bce73220917bc117a62e01be0c4a62bf0671` | `(absent)` | `5d02bce73220917bc117a62e01be0c4a62bf0671` |
| `scripts/live_run_marker.py` | `launcher` | `(absent)` | `(absent)` | `8e0bfb1cbb19938ad367227a6b358511b9f44adf` | `8e0bfb1cbb19938ad367227a6b358511b9f44adf` | `(absent)` | `8e0bfb1cbb19938ad367227a6b358511b9f44adf` |
| `scripts/read_launcher_result.py` | `launcher` | `c63ddcc2b17a020ec3313b3669eff0b1ad929dfc` | `c63ddcc2b17a020ec3313b3669eff0b1ad929dfc` | `a4e7afeb526aa9a18c45fef1c62d0a7e23ae3017` | `a4e7afeb526aa9a18c45fef1c62d0a7e23ae3017` | `(absent)` | `a4e7afeb526aa9a18c45fef1c62d0a7e23ae3017` |
| `scripts/test_hermes_agent.py` | `launcher` | `7ae790c748d6e319e5f4dc912d61bda93ef3e187` | `7ae790c748d6e319e5f4dc912d61bda93ef3e187` | `7333874d6661e6a67f031db1587db958e8c6d740` | `7333874d6661e6a67f031db1587db958e8c6d740` | `(absent)` | `7333874d6661e6a67f031db1587db958e8c6d740` |
| `scripts/test_live_run_marker.py` | `launcher` | `(absent)` | `(absent)` | `45f28e3bc90695bfcec7062395392f3768e363f7` | `45f28e3bc90695bfcec7062395392f3768e363f7` | `(absent)` | `45f28e3bc90695bfcec7062395392f3768e363f7` |
| `scripts/test_read_launcher_result.py` | `launcher` | `2c30f0fbd0fc50ccf9c05694920d6d2b74ecfed7` | `2c30f0fbd0fc50ccf9c05694920d6d2b74ecfed7` | `7ce34f20bfcfb723f719dae809a7c32d4ed1eec3` | `7ce34f20bfcfb723f719dae809a7c32d4ed1eec3` | `(absent)` | `7ce34f20bfcfb723f719dae809a7c32d4ed1eec3` |
| `scripts/test_with_live_credential.py` | `launcher-then-live` | `e70b986720be98a66582e8550dc93e4564a52884` | `e70b986720be98a66582e8550dc93e4564a52884` | `ce28f1d8607df3b195bf56f23ebff24d495261f5` | `530c2366ebb91ebd9a1bb4aef8417140dc1c1332` | `530c2366ebb91ebd9a1bb4aef8417140dc1c1332` | `530c2366ebb91ebd9a1bb4aef8417140dc1c1332` |
| `scripts/with_live_credential.py` | `launcher-then-live` | `b9e2c0ab1d80781fff681931fefc86e9e66efdf3` | `b9e2c0ab1d80781fff681931fefc86e9e66efdf3` | `fc8a3bd80773cd27de4853dcf7f553de57cfc870` | `d4bb9c4e27c5609022e08462d6ef3853737a286c` | `d4bb9c4e27c5609022e08462d6ef3853737a286c` | `d4bb9c4e27c5609022e08462d6ef3853737a286c` |

`apps/web/tests/live/README.md` must use exact 80fe blob `68318c561649d67e880bd87024bd3e90cc20afd7`. `scripts/README.md` is not in either mechanical set.

## Deterministic scripts/README.md merge

Proxy/deployment runs first and leaves `scripts/README.md` at blob `c2a31b8b58237551b698c64671a027da28ed84ff`. The immutable future driver then composes the reviewed file only under its dedicated absolute `/tmp/...` replay root: the 80fe3b68fb676a3b6589fce9aed79140bf37b667 prefix before the unique `## Disposable Caddy proof renderer\n` anchor plus the e3a2d2e662f2e606f318d35f4fccc63ba9738f7c section from that anchor through EOF. It never uses `ours`, `theirs`, a merge strategy, or a force option.

| Check | Expected |
|---|---|
| Bytes | `44854` |
| Lines | `739` |
| SHA-256 | `2a15d48344d3d00c9e6a0f95f1805ec41c251b8886487bb3b1935fdff70c2030` |
| Git blob | `d74f0c1431901f83e736389395a122c48e521a32` |
| Old CAS blob | `c2a31b8b58237551b698c64671a027da28ed84ff` |
| Mode | `100644` |

The exact merge, CAS, staged-path, binary patch, post-commit, and cleanup sequence is `/execution_driver/shell` in the JSON companion. Its future temporary file is `$REPLAY_ROOT/scripts-README.merge`; it is never placed in `${TMPDIR:-/tmp}`.

## Guarded replay gates

### Clean base and remote drift

The future driver verifies SOURCE read-only without requiring it to be clean, then creates and validates a dedicated clean-primary root. Replay refuses to start unless clean-primary resolves to its exact canonical root, is completely clean, and has these exact refs:

```text
origin/dev  729f2613af2b78d58b07918478e9102d5716f367
origin/main 3ebf8b3fe4767442490ab3053c0c1ccf84e8019f
base tree   43f86b645fc9f89d5d4aa1e6978b1f61f0b5c69f
```

It never mutates or cleans SOURCE, including unknown files. It verifies SOURCE refs/tree and canonical/lstat owner/mode/device/inode/common-directory/object-store identity read-only, atomically creates `/tmp/hermternal-task409-final-clean-primary.$$`, copies objects with a local `--no-hardlinks` clone without network or alternates, pins exact refs, checks out detached BASE, and requires complete clean status. It then creates only `/tmp/hermternal-task409-final-replay.$$`, rejects overlap among SOURCE, clean-primary, replay, and every registered/nested worktree, and bootstraps replay with a read-only clean-primary object alternate. Before the first replay mutation it requires detached `HEAD == BASE` and `HEAD^{tree} == BASE_TREE`. Before every later mutation and cleanup it requires source drift checks, clean-primary identity/status, the validated replay root, detached current HEAD/tree, both origin pins, and an exact transaction-path status allowlist.

The driver uses trusted absolute executables, argv arrays and `--` path terminators, never `eval`, and scrubs inherited Git/config/credential variables.

### Dedicated clean-primary bootstrap

SOURCE is an input, not a workspace. It may contain unknown dirty or untracked files. The future driver binds SOURCE read-only by canonical path plus `lstat` owner/mode/device/inode, Git common-directory identity, and object-store identity, then re-reads `origin/dev`, `origin/main`, and `origin/dev^{tree}` before every mutation. SOURCE alternates are rejected.

It atomically creates the fixed `/tmp/hermternal-task409-final-clean-primary.$$` root with mode `0700`; a preexisting path, symlink substitution, non-canonical parent, owner/mode/device/inode swap, or nested registered worktree is fatal. It clones locally with `--local --no-hardlinks --no-checkout --no-tags`, so objects are copied into a distinct clean-primary object store without a shared mutable alternate or network access. The driver binds the clean-primary repository, Git common directory, and object store by canonical path/lstat owner/mode/device/inode, rejects `$CLEAN_PRIMARY/.git/objects/info/alternates`, verifies `st_nlink == 1` for every regular loose-object, pack, index, keep, and info file, configures exact `origin/dev == BASE` and `origin/main == MAIN`, checks out detached `BASE`, and requires complete whole-worktree cleanliness: `git status --porcelain=v1 --untracked-files=all --ignored=all` is empty and both unstaged and staged diffs are quiet.

Replay uses clean-primary and replay only. SOURCE is never staged, checked out, mutated, deleted, moved, or used as the replay working tree. The non-replay adversarial smoke covers preexisting path, symlink substitution, alternates/shared object store, shared hardlinked object/pack/index files, ref/source drift, dirty or ignored clean-primary artifacts, inode/mode swaps, and unknown-artifact cleanup.

### Forbidden ancestry

The final candidate must not contain any forbidden source, rejected, rehearsal, provisional, marker, watermark, raw semantic, or rejected-auth endpoint as an ancestor. The check is exact: `git merge-base --is-ancestor BAD FINAL_HEAD` is accepted only when it returns `1`; `0`, `2`, or any other result is fatal. The rejected authentication range is also explicit: `d88cd9adfcef94980ae674f40d99c65e1cf9b666..f87ce048b5afc4fad7ac361baa589d47745b580b`.

Forbidden full IDs:

- `13df3d058f1d14ca07b199a45c5b01cb4bf7b020`
- `f87ce048b5afc4fad7ac361baa589d47745b580b`
- `7271e7bac836a519c3df66a93ceb3b2c5a0d8921`
- `03e2b0c828276044d1229c0200a5ac969140a344`
- `ad9bc22b7cc86e0c007a0347e2dec78fa49132a4`
- `48b58c19e4e4991d1d15321a8e39b8261937b59b`
- `c7ab4f9b0fec97b4e4de20bada6f43e57bd7d5e3`
- `1f4388b24ccf7ebc3c42b2192515ae343a52083a`
- `9d9756b2a0a20130258766ea3a532c067e2f13f6`
- `77c6701c652a6bbd23d2c32227dcd61c34dd8c33`
- `44cc58146569bc580d9fd3f78b9241102df62c97`
- `f7bf2f131fa079a4d204b86619039600d1559028`
- `293dbca7f4e992d16e848acb73dd29257ed4ad0d`
- `befb8c7e673157932f5f13242d863e64806cffac`
- `83c709bf9a22672362662f7c369b2c235f5859e9`
- `b1741699ca93262306b039771fe96282cb4142fd`
- `94b0dd97247093f5ca3eb5dee4f1e3c6926e6439`
- `d3c40687659ee645a5f03bc80cbf61ec8c49979a`
- `f54c8511e67a50fa7a00bf28e694459c77cf21c3`
- `80fe3b68fb676a3b6589fce9aed79140bf37b667`
- `221620c04bb051f2597c52bdeb16ccc55c5b2e9c`
- `027806c8596f8b9a4ce200b2fe1344e013f46685`


Rejected authentication endpoints are checked again explicitly:

- `d88cd9adfcef94980ae674f40d99c65e1cf9b666`
- `f87ce048b5afc4fad7ac361baa589d47745b580b`

Forbidden strategies remain: `-X ours`, `--strategy-option=ours`, `merge -s ours`, and force push.

### Exact final blob, patch, and ancestry checks

The future driver verifies every final matrix row independently by full blob ID, mode, regular-file type, or exact absence. It verifies the 29-path union, the four overlap paths, the 11/22/29 cardinalities, and the separate `scripts/README.md` merge. It never compares a final whole tree with a source tree.

Every range and semantic lane has a lane-specific gate: exact source parents and trees, inclusive range order/count, zero merges, exact changed-path scope, non-empty binary patch, stable patch ID, exact staged paths, `git diff --check`, and post-commit parent/tree/path/patch checks. The two projection hash commands are:

```text
/usr/bin/git -C REPLAY diff --binary --full-index --no-ext-diff --no-textconv A B -- PATH... | /usr/bin/git patch-id --stable
/usr/bin/git -C REPLAY diff --binary --full-index --no-ext-diff --no-textconv A B -- PATH... | /usr/bin/shasum -a 256
```

Approved scoped values remain. For matrix stages, these values are source-parent-to-source-child projection gates; the candidate staged patch is separately required to be non-empty, binary-aware, exact-path, and `diff --check` clean because live-only additions do not share the d3 source parent tree.

- Launcher stable patch ID `0030c185191be447cf53a54cc535c3a0ee172823`; raw SHA `abf56c277f205c229951bb6165afecb476cce08b5560872455a6d65d72b1b238`.
- Launcher mechanical stable patch ID `cd1e6446174eca48b7bca2b263c332e0f71303b1`; raw SHA `5c9f76cd27ba4c4136f324926aab1f01f00e1033b21ee0dfb81da9ac3d016942`.
- Live-proof stable patch ID `1e4799b4eaf505bd4b06e939608edabc6698fca6`; raw SHA `85a8a57fef533d9cb8a3907550a769b704ab2fb478647b16402a12ceb8558fa1`.
- Live-proof mechanical stable patch ID `304ee69ee3b7753aa516ee86f3b3053d3f9ec97b`; raw SHA `12892436be96696fa5f0261e5c238b5aa82d46267b829b5e081896ab642dd1c3`.

### Push boundary

After final equality `origin/dev == 729f2613af2b78d58b07918478e9102d5716f367` is re-read from the primary checkout, independent exact-SHA approval remains mandatory. The immutable driver stops there and contains no fetch or push command. A separate operator may consider a normal non-force push only after that approval.

## Verification fanout

These are a future, operator-run verification list only; they are not replay mutations and are intentionally non-executable Markdown. Run them only from the clean detached checkout after the immutable driver, exact marker/watermark gates, and independent approval. Live commands remain outside this offline fanout.

### Web

```text
cd apps/web && bun run check
cd apps/web && bun run typecheck
cd apps/web && bun run test:static
cd apps/web && bun run test
cd apps/web && bun run test:a11y
cd apps/web && bun run test:no-network
```

### Fixture authority and validator

```text
python3 scripts/test_fixture_registry_authority.py
python3 -O scripts/test_fixture_registry_authority.py
python3 contracts/fixtures/validator/validate.py
python3 -O contracts/fixtures/validator/validate.py
python3 contracts/fixtures/validator/test_validate.py
python3 -O contracts/fixtures/validator/test_validate.py
python3 -m unittest discover -s contracts/fixtures/validator -p 'test_*.py'
python3 -O -m unittest discover -s contracts/fixtures/validator -p 'test_*.py'
python3 -m py_compile contracts/fixtures/validator/validate.py contracts/fixtures/validator/test_validate.py
```

### Launcher and parser

```text
python3 scripts/test_hermes_agent.py
python3 -O scripts/test_hermes_agent.py
python3 scripts/test_live_run_marker.py
python3 -O scripts/test_live_run_marker.py
python3 scripts/test_read_launcher_result.py
python3 -O scripts/test_read_launcher_result.py
python3 scripts/test_with_live_credential.py
python3 -O scripts/test_with_live_credential.py
```

### Proxy and dependency unit suites

```text
python3 scripts/test_caddy_proof.py
python3 -O scripts/test_caddy_proof.py
python3 scripts/test_traefik_proof.py
python3 -O scripts/test_traefik_proof.py
python3 scripts/test_dependency_audit.py
python3 -O scripts/test_dependency_audit.py
```

### Swift

```text
cd contracts/swift-parity && swift test
cd contracts/swift-parity && swift test -c release
```

### Graph review

```text
code-review-graph update --brief
code-review-graph detect-changes
code-review-graph impact
```

## Generated-cache, clean-primary, and replay cleanup

The old broad `find .` cleanup is forbidden. After all final gates pass, the future driver removes only explicit paths. Replay artifacts must be beneath the dedicated replay root; clean-primary has a separate bound root, owner/mode/device/inode/realpath check, and repository-only contents check:

```text
/bin/rm -rf -- "$REPLAY_ROOT/replay"
/bin/rm -f -- "$REPLAY_ROOT/scripts-README.merge"
/bin/rm -f -- "$REPLAY_ROOT/matrix.snapshot.json"
/bin/rmdir -- "$REPLAY_ROOT"
/bin/rm -rf -- "$CLEAN_PRIMARY_ROOT"
```

The README temporary and immutable JSON snapshot remain available through every final gate. `REPLAY_ROOT` is an explicit final allowlist entry for the last `rmdir`, preceded by a device/inode/realpath check and an empty-root check. `CLEAN_PRIMARY_ROOT` is a separate explicit allowlist entry and is removed only after source drift, clean-primary identity, worktree separation, and exact repository-only contents checks. On failure before final gates it leaves clean-primary, replay, README temporary, and snapshot artifacts for diagnosis. It never removes files from SOURCE, a nested worktree, or an unlisted path.

## Stop on conflict

1. Stop on the first non-zero patch, scope mismatch, duplicate marker, empty lane, merge commit, ancestry violation, or `git diff --check` failure.
2. Do not stage a partial resolution.
3. Do not use an `ours` strategy or force option.
4. Abort the operation without modifying SOURCE; retain the clean-primary and replay diagnostics for review.
5. Record the lane, source SHA, parent, patch ID, and paths.
6. Regenerate a reviewed semantic child from the approved parent.
7. Obtain independent exact-SHA approval before resuming.
8. Re-run all preceding and subsequent gates from a fresh clean detached checkout.

## Historical compatibility objects

Retain these objects for compatibility and rejection checks. `contracts/fixtures/README.md` remains the authority for legacy v1/v2 fixture-registry compatibility.

| Role | Commit | Parent(s) | Tree | Stable patch ID |
|---|---|---|---|---|
| rejected marker head | `293dbca7f4e992d16e848acb73dd29257ed4ad0d` | `942153e74842ff9a70dd4ce1673e7d87692c6dcd` | `fcce71993b6bb775926af956a5218832f349cb18` | `6bed88e81afda3e08ff8045ea6055fd45fd8f641` |
| marker baseline | `44cc58146569bc580d9fd3f78b9241102df62c97` | `293dbca7f4e992d16e848acb73dd29257ed4ad0d` | `7a1ed34a609e7d2ff39a5bc93d5ce3d2e7f5e3e5` | `aef952124c1ebd8ee1c665f33bdf25b1ce287da1` |
| rejected watermark | `77c6701c652a6bbd23d2c32227dcd61c34dd8c33` | `1f4388b24ccf7ebc3c42b2192515ae343a52083a` | `6014460cdb6c9a835826a3da96668630dbac1854` | `906dbeb53cabedf7d9f5e0baf347e476430f0a63` |
| watermark baseline | `f7bf2f131fa079a4d204b86619039600d1559028` | `77c6701c652a6bbd23d2c32227dcd61c34dd8c33` | `4b001b0c19cc5954e506846767f062ff61090638` | `e2a2780752973ffb842c5bd744b776cf6097507b` |
| approved watermark child | `f054bfe71d98129b81c10367ca27540da6243496` | `f7bf2f131fa079a4d204b86619039600d1559028` | `e5b498823c94e6985e02bf06ba896c6a6cccdb96` | `686ca24bce375c22ea898afce066bb119f819377` |
| authentication rehearsal | `b1741699ca93262306b039771fe96282cb4142fd` | `1f4388b24ccf7ebc3c42b2192515ae343a52083a` | `54916a4a3baad005631cd6c5193392d44010c60e` | `313527664bea572980abed8c0dee582f931597ce` |
| authentication content source | `83c709bf9a22672362662f7c369b2c235f5859e9` | `f87ce048b5afc4fad7ac361baa589d47745b580b` | `c23474de976cbd12497fc109db9acdac62966ec0` | `261363bf146f59c9f33d97728034c84acbccf90a` |
| renderer rejected source | `9d9756b2a0a20130258766ea3a532c067e2f13f6` | `9512f7ca4a1c99fd1a87b947617a3a1744d8674a` | `e7208548cdb9e8cbc05938acd7126d484f0c7257` | `b5ad06f1079e99655224d6bf60c90c147c683ecb` |
| renderer approved semantic child | `befb8c7e673157932f5f13242d863e64806cffac` | `9d9756b2a0a20130258766ea3a532c067e2f13f6` | `e7af1ae07ef9c5d79d30d64b380da20bd5998651` | `765ab638cb0065dc7aa0291925fc86e59720af35` |

## Canonical machine-readable ordered execution driver

The JSON companion is the machine-readable source of truth at `/execution_driver`. The Markdown code block below is byte-identical to its `/execution_driver/shell` value; the recorded SHA-256 binds the two artifacts.

- Driver schema: `hermternal.task409.execution-driver.v1`
- Driver shell SHA-256: `9995382f83d26bb22a8c7641c1dc2f5a7157b7530f9eaadd0b73e329ecf2e75f`
- Invocation argv: ["/usr/bin/env","-i","PATH=/usr/bin:/bin","HOME=/dev/null","LANG=C","LC_ALL=C","GIT_CONFIG_NOSYSTEM=1","GIT_CONFIG_GLOBAL=/dev/null","GIT_CONFIG_SYSTEM=/dev/null","GIT_TERMINAL_PROMPT=0","GIT_OPTIONAL_LOCKS=0","GIT_NO_REPLACE_OBJECTS=1","/bin/bash","-euo","pipefail","-s"]
- Future-only invocation: /usr/bin/env -i PATH=/usr/bin:/bin HOME=/dev/null LANG=C LC_ALL=C GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 /bin/bash -euo pipefail -s
- Source repository: `/home/kayg/Developer/hermternal-397-guarded` (read-only; source cleanliness is not required)
- Clean-primary root: `/tmp/hermternal-task409-final-clean-primary.$$` with repository `/tmp/hermternal-task409-final-clean-primary.$$/repository`
- Replay root: `/tmp/hermternal-task409-final-replay.$$`
- Fresh extraction boundary: extract `/execution_driver/shell` from this exact Markdown/JSON pair, require shell SHA-256 `9995382f83d26bb22a8c7641c1dc2f5a7157b7530f9eaadd0b73e329ecf2e75f`, require normalized JSON identity `8af9f293a93ebdf0b7e834135898da1a2d97b0ff9efb26a995468f602d3c8e85`, then invoke only the freshly extracted body. Standalone `/tmp/hermternal-task409-approved-driver.sh` is stale and non-authoritative; never reuse it.

- Identity parity: replay-root owner-after-creation and owner-at-every-mutation/cleanup-boundary checks are duplicated exactly in JSON validation metadata; clean-primary object-store `st_nlink == 1`, no-alternates, and whole-worktree cleanliness proofs are bound at bootstrap and mutation/cleanup boundaries.
- Swift source SHA: `221620c04bb051f2597c52bdeb16ccc55c5b2e9c`
- Matrix identity: exact source bytes are validated with normalized SHA-256 `8af9f293a93ebdf0b7e834135898da1a2d97b0ff9efb26a995468f602d3c8e85`; after root creation they are read once through `O_NOFOLLOW`, written with `O_CREAT|O_EXCL` at mode `0600` to `$REPLAY_ROOT/matrix.snapshot.json`, and every mutation boundary verifies device/inode/size/realpath.
- Byte-exact Markdown extraction: raw bytes, canonical section heading, first exact ` ```bash\n ` opening, first exact ` ``` ` closing, and no trimming or newline normalization; body and JSON shell are `289319` bytes, SHA-256 `9995382f83d26bb22a8c7641c1dc2f5a7157b7530f9eaadd0b73e329ecf2e75f`, terminal byte `0a`.
- Bash compatibility: the trusted `/bin/bash` driver is smoke-tested on macOS Bash 3.2.57 with nounset-safe empty and non-empty indexed-array paths, including a space-bearing path and duplicate suppression; associative arrays and `mapfile` are not used.
- Final cleanup order: final gates, replay checkout, README temporary, immutable matrix snapshot, empty replay-root identity check and `rmdir`, then clean-primary identity/content check and cleanup; failures retain clean-primary, replay root, README temporary, and snapshot.

| Order | Step | Boundary | Gate |
|---:|---|---|---|
| 1 | `scrub-env-and-static-preflight` | `read-only` | trusted executables, exact /usr/bin/env -i allowlist, scrubbed Git env, exact refs/tree, full ID types, ranges, sets, blobs, README, patch IDs, raw hashes, and rejected auth endpoints |
| 2 | `verify-source-read-only` | `read-only` | SOURCE may be noisy but exact origin/dev, origin/main, base tree, canonical path, lstat owner/mode/device/inode, Git common directory, object store, and no-alternates identity are bound and rechecked |
| 3 | `create-dedicated-clean-primary-root` | `clean-primary-root` | fixed absolute /tmp root is atomically exclusive, mode 0700, canonical, non-symlink, and outside SOURCE/replay/worktrees |
| 4 | `bootstrap-clean-primary` | `clean-primary-root` | local no-hardlink object copy without network or alternates, every regular copied object-store file st_nlink==1, exact refs, detached BASE checkout, and complete whole-worktree clean status including ignored/untracked files |
| 5 | `create-dedicated-replay-root` | `replay-root` | absolute /tmp root outside SOURCE, clean-primary, and every registered/nested worktree |
| 6 | `bootstrap-detached-base` | `replay-root` | standalone repository, read-only clean-primary object alternate, origin pins, detached HEAD==BASE, HEAD tree==BASE_TREE |
| 7 | `renderer-lifecycle-range-and-projection` | `replay` | range source-parent/path/patch gates followed by one semantic projection |
| 8 | `static-manifest-range` | `replay` | inclusive order, zero merges, duplicate rejection, exact staged paths, declared target blob/mode/type postconditions, binary patch and post-commit gates |
| 9 | `authentication-range-and-projection` | `replay` | range plus 23-path semantic projection; rejected auth endpoints stay forbidden ancestors |
| 10 | `fixture-authority-range-and-projection` | `replay` | authority range plus detached correction projection |
| 11 | `apple-benchmark-range` | `replay` | exact inclusive range and source ledger gates |
| 12 | `proxy-deployment-range` | `replay` | exact range and pinned proxy README precondition |
| 13 | `launcher-stage-one` | `replay` | 10-path matrix CAS from d3c40687659ee645a5f03bc80cbf61ec8c49979a; README excluded |
| 14 | `stage-two-overlap-gate` | `replay` | verify the three d3c40687659ee645a5f03bc80cbf61ec8c49979a overlap paths and proxy README before live stage |
| 15 | `dependency-audit-correction` | `replay` | 3-path source-parent semantic CAS projection |
| 16 | `swift-parity-correction` | `replay` | normalized Swift source 221620c04bb051f2597c52bdeb16ccc55c5b2e9c content projection without inheriting its ancestry |
| 17 | `live-stage-two` | `replay` | 21-path matrix CAS from 80fe3b68fb676a3b6589fce9aed79140bf37b667 after exact d3c40687659ee645a5f03bc80cbf61ec8c49979a overlap checks |
| 18 | `separate-readme-merge` | `replay` | compose, shape/hash/blob check, old CAS, target verification, separate commit |
| 19 | `final-gates` | `read-only` | exact 29 final blobs/modes, README values, binary post-commit gates, and forbidden ancestry rc=1 |
| 20 | `remote-equality-and-approval-boundary` | `read-only` | re-read origin/dev==BASE; require independent approval; never push |
| 21 | `explicit-allowlisted-cleanup` | `replay-root` | after final gates, remove only replay checkout, README temp, immutable JSON snapshot, and separately validated clean-primary root; verify identity and empty-root conditions; never find . |

The driver has no fetch, push, live, socket, credential, or broad cleanup operation. It requires the exact /usr/bin/env -i allowlist, rejects numbered/config/PYTHONPATH/runtime overrides, binds projection CAS to declared source-parent and stage trees, verifies range target blobs/modes/types, and is intentionally not run during artifact production.

```bash
# Candidate4 generated Python escape invariant: one source backslash; no global escape replacement.
#!/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

# Task #409 / artifact #464. This is an offline future replay only. It reads local
# objects through a read-only alternate object database and never fetches, pushes,
# contacts a service, starts Hermes, opens a socket, or reads credentials.
readonly GIT=/usr/bin/git
readonly PYTHON=/usr/bin/python3
readonly BASH=/bin/bash
readonly ENV=/usr/bin/env
readonly MKDIR=/bin/mkdir
readonly RM=/bin/rm
readonly RMDIR=/bin/rmdir
readonly CUT=/usr/bin/cut
readonly SHASUM=/usr/bin/shasum
readonly SOURCE=/home/kayg/Developer/hermternal-397-guarded
readonly MARKDOWN=/tmp/hermternal-397-integrate/handover/issue-397/task464-candidate5-linux-v1-final/candidate-five.md
readonly MATRIX_SOURCE=/tmp/hermternal-397-integrate/handover/issue-397/task464-candidate5-linux-v1-final/candidate-five.json
MATRIX="$MATRIX_SOURCE"
readonly MATRIX_EXPECTED_BINDING_SHA256='8af9f293a93ebdf0b7e834135898da1a2d97b0ff9efb26a995468f602d3c8e85'
MATRIX_BOUND=0
MATRIX_SOURCE_VALIDATED=0
MATRIX_SNAPSHOT_DEVICE=''
MATRIX_SNAPSHOT_INODE=''
MATRIX_SNAPSHOT_SIZE=''
MATRIX_SNAPSHOT_REALPATH=''
readonly BASE=729f2613af2b78d58b07918478e9102d5716f367
readonly BASE_TREE=43f86b645fc9f89d5d4aa1e6978b1f61f0b5c69f
readonly MAIN=3ebf8b3fe4767442490ab3053c0c1ccf84e8019f
readonly PROXY=e3a2d2e662f2e606f318d35f4fccc63ba9738f7c
readonly LAUNCHER=d3c40687659ee645a5f03bc80cbf61ec8c49979a
readonly LIVE=80fe3b68fb676a3b6589fce9aed79140bf37b667
readonly SWIFT=221620c04bb051f2597c52bdeb16ccc55c5b2e9c
readonly REJECTED_AUTH_LEFT=d88cd9adfcef94980ae674f40d99c65e1cf9b666
readonly REJECTED_AUTH_RIGHT=f87ce048b5afc4fad7ac361baa589d47745b580b
readonly CLEAN_PRIMARY_ROOT="/tmp/hermternal-task409-final-clean-primary.$$"
readonly CLEAN_PRIMARY="$CLEAN_PRIMARY_ROOT/repository"
readonly REPLAY_ROOT="/tmp/hermternal-task409-final-replay.$$"
readonly REPLAY="$REPLAY_ROOT/replay"
readonly README_TMP="$REPLAY_ROOT/scripts-README.merge"
readonly MATRIX_SNAPSHOT="$REPLAY_ROOT/matrix.snapshot.json"
SOURCE_BOUND=0
SOURCE_REALPATH=''
SOURCE_DEVICE=''
SOURCE_INODE=''
SOURCE_UID=''
SOURCE_MODE=''
SOURCE_GIT_DIR=''
SOURCE_GIT_COMMON_DIR=''
SOURCE_OBJECTS=''
SOURCE_GIT_DEVICE=''
SOURCE_GIT_INODE=''
SOURCE_GIT_UID=''
SOURCE_GIT_MODE=''
SOURCE_COMMON_DEVICE=''
SOURCE_COMMON_INODE=''
SOURCE_COMMON_UID=''
SOURCE_COMMON_MODE=''
SOURCE_OBJECTS_DEVICE=''
SOURCE_OBJECTS_INODE=''
SOURCE_OBJECTS_UID=''
SOURCE_OBJECTS_MODE=''
SOURCE_CAPTURE_DEV=''
SOURCE_CAPTURE_MAIN=''
SOURCE_CAPTURE_TREE=''
CLEAN_PRIMARY_ROOT_BOUND=0
CLEAN_PRIMARY_ROOT_DEVICE=''
CLEAN_PRIMARY_ROOT_INODE=''
CLEAN_PRIMARY_ROOT_UID=''
CLEAN_PRIMARY_ROOT_MODE=''
CLEAN_PRIMARY_ROOT_REALPATH=''
CLEAN_PRIMARY_ROOT_NLINK=''
CLEAN_PRIMARY_PARENT_DEVICE=''
CLEAN_PRIMARY_PARENT_INODE=''
CLEAN_PRIMARY_PARENT_UID=''
CLEAN_PRIMARY_PARENT_MODE=''
CLEAN_PRIMARY_PARENT_NLINK=''
CLEAN_PRIMARY_REPOSITORY_BOUND=0
CLEAN_PRIMARY_REPOSITORY_DEVICE=''
CLEAN_PRIMARY_REPOSITORY_INODE=''
CLEAN_PRIMARY_REPOSITORY_UID=''
CLEAN_PRIMARY_REPOSITORY_MODE=''
CLEAN_PRIMARY_REPOSITORY_NLINK=''
CLEAN_PRIMARY_BOUND=0
CLEAN_PRIMARY_REALPATH=''
CLEAN_PRIMARY_DEVICE=''
CLEAN_PRIMARY_INODE=''
CLEAN_PRIMARY_UID=''
CLEAN_PRIMARY_MODE=''
CLEAN_PRIMARY_GIT_DIR=''
CLEAN_PRIMARY_COMMON_DIR=''
CLEAN_PRIMARY_OBJECTS=''
CLEAN_PRIMARY_GIT_DEVICE=''
CLEAN_PRIMARY_GIT_INODE=''
CLEAN_PRIMARY_GIT_UID=''
CLEAN_PRIMARY_GIT_MODE=''
CLEAN_PRIMARY_COMMON_DEVICE=''
CLEAN_PRIMARY_COMMON_INODE=''
CLEAN_PRIMARY_COMMON_UID=''
CLEAN_PRIMARY_COMMON_MODE=''
CLEAN_PRIMARY_OBJECTS_DEVICE=''
CLEAN_PRIMARY_OBJECTS_INODE=''
CLEAN_PRIMARY_OBJECTS_UID=''
CLEAN_PRIMARY_OBJECTS_MODE=''
REPLAY_ROOT_BOUND=0
REPLAY_ROOT_DEVICE=''
REPLAY_ROOT_INODE=''
REPLAY_ROOT_UID=''
REPLAY_ROOT_MODE=''
REPLAY_ROOT_REALPATH=''
REPLAY_GIT_BOUND=0
REPLAY_ROOT_NLINK=''
REPLAY_PARENT_DEVICE=''
REPLAY_PARENT_INODE=''
REPLAY_PARENT_UID=''
REPLAY_PARENT_MODE=''
REPLAY_PARENT_NLINK=''
REPLAY_CHECKOUT_BOUND=0
REPLAY_CHECKOUT_PRESENT=0
REPLAY_CHECKOUT_DEVICE=''
REPLAY_CHECKOUT_INODE=''
REPLAY_CHECKOUT_UID=''
REPLAY_CHECKOUT_MODE=''
REPLAY_CHECKOUT_NLINK=''
readonly COMMITTER_NAME='Task409 guarded replay'
readonly COMMITTER_EMAIL='task409-replay@localhost'

# The exact /usr/bin/env -i invocation is mandatory. The allowlist fails closed before
# any Git or Python operation, so numbered Git config variables, GIT_CONFIG_PARAMETERS,
# PYTHONPATH, Python runtime overrides, and other inherited launch overrides cannot pass.
fail() {
  printf 'task409-final-driver: %s\n' "$*" >&2
  exit 1
}
secure_temp_file() {
  local directory="$1" prefix="$2" path
  path="$($PYTHON - "$directory" "$prefix" <<'PY'
import os
import sys
import tempfile
directory, prefix = sys.argv[1:]
fd, path = tempfile.mkstemp(prefix='.task464-' + prefix + '.', dir=directory)
os.fchmod(fd, 0o600)
os.close(fd)
print(path)
PY
)" || fail "secure temporary-file creation failed: $prefix"
  case "$path" in "$directory"/.task464-*) ;; *) fail "temporary file escaped its directory: $path" ;; esac
  test -f "$path" || fail "temporary file was not created: $path"
  printf '%s\n' "$path"
}
cleanup_temp_file() {
  local path="$1"
  case "$path" in "$REPLAY_ROOT"/.task464-*|/tmp/.task464-*) ;; *) fail "temporary cleanup path escaped its allowlist: $path" ;; esac
  "$RM" -f -- "$path"
  test ! -e "$path" || fail "temporary file cleanup failed: $path"
}
producer_to_file() {
  local label="$1" directory="$2" output status
  shift 2
  output="$(secure_temp_file "$directory" "$label")"
  set +e
  "$@" > "$output"
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    cleanup_temp_file "$output"
    fail "record producer failed ($label), rc=$status"
  fi
  test -s "$output" || { cleanup_temp_file "$output"; fail "record producer emitted no rows: $label"; }
  printf '%s\n' "$output"
}
assert_environment() {
  local env_file env_status name ignored
  env_file="$(secure_temp_file /tmp environment)"
  set +e
  "$ENV" > "$env_file"
  env_status=$?
  set -e
  test "$env_status" -eq 0 || { cleanup_temp_file "$env_file"; fail "environment enumeration failed: $env_status"; }
  test -s "$env_file" || { cleanup_temp_file "$env_file"; fail "environment enumeration was empty"; }
  while IFS='=' read -r name ignored; do
    case "$name" in
      GIT_CONFIG_PARAMETERS|GIT_CONFIG_COUNT|GIT_CONFIG_KEY_*|GIT_CONFIG_VALUE_*|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|PYTHONUSERBASE|PYTHONINSPECT|PYTHONWARNINGS|BASH_ENV|ENV|CDPATH|NODE_OPTIONS|RUBYOPT|PERL5OPT|DYLD_*|LD_*)
        cleanup_temp_file "$env_file"; fail "forbidden inherited environment variable: $name" ;;
      PATH|HOME|LANG|LC_ALL|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_TERMINAL_PROMPT|GIT_OPTIONAL_LOCKS|GIT_NO_REPLACE_OBJECTS|GIT_NO_LAZY_FETCH|PWD|SHLVL|_) ;;
      *) cleanup_temp_file "$env_file"; fail "environment variable is not allowlisted: $name" ;;
    esac
  done < "$env_file"
  cleanup_temp_file "$env_file"
}
assert_environment
export PATH=/usr/bin:/bin
export HOME=/dev/null
export LANG=C
export LC_ALL=C
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_TERMINAL_PROMPT=0
export GIT_OPTIONAL_LOCKS=0
export GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_LAZY_FETCH=1

CURRENT_HEAD=''
CURRENT_TREE=''
BOOTSTRAP_HEAD=''
BOOTSTRAP_TREE=''
REPLAY_READY=0
DIRTY_PATHS=()
APPLIED_PATCH_IDS=''
CLEANUP_ALLOWLIST=()
CLEAN_PRIMARY_CLEANUP_ALLOWLIST=()
BASH_ARRAY_SMOKE_DONE=0
CLEAN_PRIMARY_SMOKE_DONE=0

git_hermetic() {
  "$ENV" -i \
    PATH=/usr/bin:/bin \
    HOME=/dev/null \
    LANG=C \
    LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_SYSTEM=/dev/null \
    GIT_TERMINAL_PROMPT=0 \
    GIT_OPTIONAL_LOCKS=0 \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_NO_LAZY_FETCH=1 \
    "$GIT" \
    --no-replace-objects \
    --no-lazy-fetch \
    --no-optional-locks \
    -c core.hooksPath=/dev/null \
    -c protocol.allow=never \
    "$@"
}
git_source() {
  git_hermetic -C "$SOURCE" "$@"
}
git_primary() {
  git_hermetic -C "$CLEAN_PRIMARY" "$@"
}
git_replay() {
  git_hermetic -C "$REPLAY" "$@"
}
patch_id_stable() {
  git_hermetic patch-id --stable
}

bind_source_identity() {
  test "$SOURCE_BOUND" -eq 0 || fail "source identity already bound"
  local git_dir common_dir objects fields
  git_dir="$(git_source rev-parse --absolute-git-dir)"
  common_dir="$(git_source rev-parse --git-common-dir)"
  objects="$(git_source rev-parse --git-path objects)"
  SOURCE_CAPTURE_DEV="$(git_source rev-parse origin/dev)"
  SOURCE_CAPTURE_MAIN="$(git_source rev-parse origin/main)"
  SOURCE_CAPTURE_TREE="$(git_source rev-parse "${SOURCE_CAPTURE_DEV}^{tree}")"
  test "$SOURCE_CAPTURE_DEV" = "$BASE" || fail "source origin/dev is not BASE"
  test "$SOURCE_CAPTURE_MAIN" = "$MAIN" || fail "source origin/main is not MAIN"
  test "$SOURCE_CAPTURE_TREE" = "$BASE_TREE" || fail "source base tree is not BASE_TREE"
  fields="$($PYTHON - "$SOURCE" "$git_dir" "$common_dir" "$objects" <<'PY'
import os
import stat
import sys
source, git_dir, common_dir, objects = sys.argv[1:]
def canonical(base, value):
    return os.path.realpath(value if os.path.isabs(value) else os.path.join(base, value))
def checked(path, label):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != path:
        raise SystemExit(label + ' is not a canonical non-symlink directory')
    return path, st
def values(st):
    return [str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')]
source_path, source_st = checked(source, 'source')
git_path, git_st = checked(canonical(source, git_dir), 'source Git directory')
common_path, common_st = checked(canonical(source, common_dir), 'source common directory')
objects_path, objects_st = checked(canonical(source, objects), 'source object store')
if os.path.lexists(os.path.join(objects_path, 'info', 'alternates')):
    raise SystemExit('source object store has alternates')
print('\t'.join([source_path, git_path, common_path, objects_path] + values(source_st) + values(git_st) + values(common_st) + values(objects_st)))
PY
)"
  IFS=$'\t' read -r SOURCE_REALPATH SOURCE_GIT_DIR SOURCE_GIT_COMMON_DIR SOURCE_OBJECTS \
    SOURCE_DEVICE SOURCE_INODE SOURCE_UID SOURCE_MODE SOURCE_GIT_DEVICE SOURCE_GIT_INODE SOURCE_GIT_UID SOURCE_GIT_MODE \
    SOURCE_COMMON_DEVICE SOURCE_COMMON_INODE SOURCE_COMMON_UID SOURCE_COMMON_MODE SOURCE_OBJECTS_DEVICE SOURCE_OBJECTS_INODE SOURCE_OBJECTS_UID SOURCE_OBJECTS_MODE <<< "$fields"
  test "$SOURCE_REALPATH" = "$SOURCE" || fail "source canonical path was not bound"
  SOURCE_BOUND=1
  assert_source_binding
}

assert_source_binding() {
  test "$SOURCE_BOUND" -eq 1 || fail "source identity is not bound"
  local git_dir common_dir objects
  git_dir="$(git_source rev-parse --absolute-git-dir)"
  common_dir="$(git_source rev-parse --git-common-dir)"
  objects="$(git_source rev-parse --git-path objects)"
  test "$(git_source rev-parse origin/dev)" = "$SOURCE_CAPTURE_DEV" || fail "source origin/dev drifted"
  test "$(git_source rev-parse origin/main)" = "$SOURCE_CAPTURE_MAIN" || fail "source origin/main drifted"
  test "$(git_source rev-parse "${SOURCE_CAPTURE_DEV}^{tree}")" = "$SOURCE_CAPTURE_TREE" || fail "source tree drifted"
  test "$SOURCE_CAPTURE_DEV" = "$BASE" || fail "source BASE drifted"
  test "$SOURCE_CAPTURE_MAIN" = "$MAIN" || fail "source MAIN drifted"
  test "$SOURCE_CAPTURE_TREE" = "$BASE_TREE" || fail "source BASE_TREE drifted"
  "$PYTHON" - "$SOURCE" "$git_dir" "$common_dir" "$objects" "$SOURCE_REALPATH" "$SOURCE_GIT_DIR" "$SOURCE_GIT_COMMON_DIR" "$SOURCE_OBJECTS" \
    "$SOURCE_DEVICE" "$SOURCE_INODE" "$SOURCE_UID" "$SOURCE_MODE" "$SOURCE_GIT_DEVICE" "$SOURCE_GIT_INODE" "$SOURCE_GIT_UID" "$SOURCE_GIT_MODE" \
    "$SOURCE_COMMON_DEVICE" "$SOURCE_COMMON_INODE" "$SOURCE_COMMON_UID" "$SOURCE_COMMON_MODE" "$SOURCE_OBJECTS_DEVICE" "$SOURCE_OBJECTS_INODE" "$SOURCE_OBJECTS_UID" "$SOURCE_OBJECTS_MODE" <<'PY'
import os
import stat
import sys
(source, git_dir, common_dir, objects, expected_source, expected_git, expected_common, expected_objects, *values) = sys.argv[1:]
def canonical(base, value):
    return os.path.realpath(value if os.path.isabs(value) else os.path.join(base, value))
def check(path, expected, wanted, label):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != expected or expected != path:
        raise SystemExit(label + ' path changed')
    actual = [str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')]
    if actual != wanted:
        raise SystemExit(label + ' lstat identity changed')
check(source, expected_source, values[0:4], 'source')
check(canonical(source, git_dir), expected_git, values[4:8], 'source Git directory')
check(canonical(source, common_dir), expected_common, values[8:12], 'source common directory')
check(canonical(source, objects), expected_objects, values[12:16], 'source object store')
if os.path.lexists(os.path.join(expected_objects, 'info', 'alternates')):
    raise SystemExit('source object store alternates appeared')
PY
}

create_clean_primary_root() {
  test "${CLEAN_PRIMARY_ROOT_BOUND}" -eq 0 || fail "create clean primary root already bound"
  assert_root_shape
  assert_worktree_separation
  local identity
  identity="$($PYTHON - "create clean primary root" "${CLEAN_PRIMARY_ROOT}" "${CLEAN_PRIMARY}" "$SOURCE" "$CLEAN_PRIMARY" "$CLEAN_PRIMARY_BOUND" <<'PY'

import os
import stat
import subprocess
import sys

label, root, child, source, clean, clean_bound = sys.argv[1:]
root = os.path.abspath(root)
child = os.path.abspath(child)
source = os.path.abspath(source)
clean = os.path.abspath(clean)
if os.path.realpath(root) != root or os.path.realpath(child) != child:
    raise SystemExit(f'{label} root/child path is not canonical')
if os.path.dirname(child) != root or os.path.basename(child) not in ('repository', 'replay'):
    raise SystemExit(f'{label} child is not an exact root child')
parent = os.path.dirname(root)
if os.path.realpath(parent) != parent:
    raise SystemExit(f'{label} parent is not canonical')

ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}

def identity(st):
    return (str(st.st_dev), str(st.st_ino), str(st.st_uid),
            format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink))

def occupied(raw, repo, owner):
    if not isinstance(raw, str) or not raw or '\x00' in raw:
        raise SystemExit(f'{owner} registry has a malformed empty worktree path')
    absolute = raw if os.path.isabs(raw) else os.path.abspath(os.path.join(repo, raw))
    forms = tuple(dict.fromkeys((raw, absolute, os.path.normpath(absolute), os.path.realpath(absolute))))
    try:
        st = os.lstat(absolute)
    except FileNotFoundError:
        # Stale/prunable paths remain lexical occupancy evidence. They do not
        # need an lstat identity until they exist again.
        return forms, ('missing',)
    except OSError as exc:
        raise SystemExit(f'{owner} registered worktree lstat failed: {raw}: {exc}')
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(absolute) != absolute:
        raise SystemExit(f'{owner} registered worktree is not a canonical real directory: {raw}')
    return forms, ('present', *identity(st))

def parse_registry(output, owner, repo):
    # Each porcelain block must contain exactly one non-empty worktree path.
    # Locked, prunable, duplicate, and stale records are retained; malformed
    # blocks fail closed rather than becoming an unoccupied empty record.
    records = []
    block = []
    def finish(lines):
        if not lines:
            return
        paths = [line[9:] for line in lines if line.startswith('worktree ')]
        if any(line == 'worktree' for line in lines) or len(paths) != 1 or not paths[0]:
            raise SystemExit(f'{owner} registry block is malformed or ambiguous')
        raw = paths[0]
        forms, state = occupied(raw, repo, owner)
        records.append((raw, forms, state, tuple(lines)))
    for line in output.splitlines():
        if line == '':
            finish(block)
            block = []
        else:
            block.append(line)
    finish(block)
    return tuple(records)

def registry_snapshot():
    repos = [('source', source)]
    if clean_bound == '1':
        repos.append(('clean-primary', clean))
    rows = []
    for owner, repo in repos:
        output = subprocess.check_output([
            '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks',
            '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-c', 'protocol.allow=never',
            'worktree', 'list', '--porcelain',
        ], env=ENV, text=True)
        rows.append((owner, output, parse_registry(output, owner, repo)))
    return tuple(rows)

def overlap(a, b):
    if a == b:
        return True
    if not os.path.isabs(a) or not os.path.isabs(b):
        return False
    try:
        return os.path.commonpath([a, b]) in (a, b)
    except ValueError:
        return False

def validate_registry(rows, candidate):
    candidate_forms = (candidate, os.path.realpath(candidate))
    for owner, _output, records in rows:
        repo = source if owner == 'source' else clean
        own_forms, _own_state = occupied(repo, repo, owner)
        own_forms = set(own_forms)
        for raw, entry_forms, _state, _lines in records:
            if set(entry_forms) & own_forms:
                continue
            if any(overlap(item, target) for item in entry_forms for target in candidate_forms):
                raise SystemExit(f'registered/nested worktree overlaps {candidate}: {raw}')

before_registry = registry_snapshot()
validate_registry(before_registry, root)
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    parent_before = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_before.st_mode) or os.path.realpath(parent) != parent:
        raise SystemExit(f'{label} parent descriptor is unsafe')
    name = os.path.basename(root)
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise SystemExit(f'{label} root already exists')
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    root_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        root_first = os.fstat(root_fd)
        if not stat.S_ISDIR(root_first.st_mode) or stat.S_IMODE(root_first.st_mode) != 0o700:
            raise SystemExit(f'{label} root descriptor is unsafe')
        os.mkdir(os.path.basename(child), 0o700, dir_fd=root_fd)
        child_fd = os.open(os.path.basename(child), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            child_stat = os.fstat(child_fd)
            if not stat.S_ISDIR(child_stat.st_mode) or stat.S_IMODE(child_stat.st_mode) != 0o700:
                raise SystemExit(f'{label} child descriptor is unsafe')
            root_after = os.fstat(root_fd)
            parent_after = os.fstat(parent_fd)
            root_final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            child_final = os.stat(os.path.basename(child), dir_fd=root_fd, follow_symlinks=False)
            os.fsync(root_fd)
            os.fsync(parent_fd)
        finally:
            os.close(child_fd)
    finally:
        os.close(root_fd)
finally:
    os.close(parent_fd)

def ident(st):
    return (str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink))
if ident(parent_before) != ident(parent_after):
    raise SystemExit(f'{label} parent changed during root/child creation')
if ident(root_after) != ident(root_final) or ident(child_stat) != ident(child_final):
    raise SystemExit(f'{label} root/child final identity changed during creation')
after_registry = registry_snapshot()
if after_registry != before_registry:
    raise SystemExit(f'{label} registered worktree registry changed during root/child creation')
if os.path.realpath(root) != root or os.path.realpath(child) != child:
    raise SystemExit(f'{label} root/child became noncanonical')
print('\t'.join([root, *ident(parent_after), *ident(root_after), child, *ident(child_final)]))

PY
)"
  IFS=$'\t' read -r \
    CLEAN_PRIMARY_ROOT_REALPATH \
    CLEAN_PRIMARY_PARENT_DEVICE CLEAN_PRIMARY_PARENT_INODE CLEAN_PRIMARY_PARENT_UID CLEAN_PRIMARY_PARENT_MODE CLEAN_PRIMARY_PARENT_NLINK \
    CLEAN_PRIMARY_ROOT_DEVICE CLEAN_PRIMARY_ROOT_INODE CLEAN_PRIMARY_ROOT_UID CLEAN_PRIMARY_ROOT_MODE CLEAN_PRIMARY_ROOT_NLINK \
    CLEAN_PRIMARY_REPOSITORY_REALPATH CLEAN_PRIMARY_REPOSITORY_DEVICE CLEAN_PRIMARY_REPOSITORY_INODE CLEAN_PRIMARY_REPOSITORY_UID CLEAN_PRIMARY_REPOSITORY_MODE CLEAN_PRIMARY_REPOSITORY_NLINK <<< "$identity"
  test "${CLEAN_PRIMARY_ROOT_REALPATH}" = "${CLEAN_PRIMARY_ROOT}" || fail "create clean primary root canonical binding failed"
  test "${CLEAN_PRIMARY_REPOSITORY_REALPATH}" = "${CLEAN_PRIMARY}" || fail "create clean primary root child canonical binding failed"
  CLEAN_PRIMARY_ROOT_BOUND=1
  CLEAN_PRIMARY_REPOSITORY_BOUND=1
  CLEAN_PRIMARY_REPOSITORY_PRESENT=1
  assert_root_shape
  assert_worktree_separation
}



bind_clean_primary_identity() {
  test "$CLEAN_PRIMARY_ROOT_BOUND" -eq 1 || fail "clean-primary root is not bound"
  test "$CLEAN_PRIMARY_BOUND" -eq 0 || fail "clean-primary identity already bound"
  local git_dir common_dir objects fields
  assert_root_shape
  assert_worktree_separation
  git_dir="$(git_primary rev-parse --absolute-git-dir)"
  assert_root_shape
  assert_worktree_separation
  common_dir="$(git_primary rev-parse --git-common-dir)"
  assert_root_shape
  assert_worktree_separation
  objects="$(git_primary rev-parse --git-path objects)"
  assert_root_shape
  assert_worktree_separation
  fields="$($PYTHON - "$CLEAN_PRIMARY_ROOT" "$CLEAN_PRIMARY" "$SOURCE_OBJECTS" "$SOURCE_GIT_COMMON_DIR" "$git_dir" "$common_dir" "$objects" <<'PY'
import os
import stat
import sys
root, repo, source_objects, source_common, git_dir, common_dir, objects = sys.argv[1:]
def canonical(base, value):
    return os.path.realpath(value if os.path.isabs(value) else os.path.join(base, value))
def checked(path, label):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != path:
        raise SystemExit(label + ' is not a canonical non-symlink directory')
    return path, st
def values(st):
    return [str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')]
root_path, root_st = checked(root, 'clean-primary root')
if stat.S_IMODE(root_st.st_mode) != 0o700:
    raise SystemExit('clean-primary root mode is not 0700')
repo_path, repo_st = checked(repo, 'clean-primary repository')
if repo_path == root_path or os.path.commonpath([repo_path, root_path]) != root_path:
    raise SystemExit('clean-primary repository escaped its root')
git_path, git_st = checked(canonical(repo, git_dir), 'clean-primary Git directory')
common_path, common_st = checked(canonical(repo, common_dir), 'clean-primary common directory')
objects_path, objects_st = checked(canonical(repo, objects), 'clean-primary object store')
if os.path.lexists(os.path.join(objects_path, 'info', 'alternates')):
    raise SystemExit('clean-primary has a mutable alternate')
if os.path.samefile(objects_path, source_objects) or os.path.samefile(common_path, source_common):
    raise SystemExit('clean-primary shares SOURCE storage')
print('\t'.join([repo_path, git_path, common_path, objects_path] + values(root_st) + values(repo_st) + values(git_st) + values(common_st) + values(objects_st)))
PY
)"
  IFS=$'\t' read -r CLEAN_PRIMARY_REALPATH CLEAN_PRIMARY_GIT_DIR CLEAN_PRIMARY_COMMON_DIR CLEAN_PRIMARY_OBJECTS \
    CLEAN_PRIMARY_ROOT_DEVICE CLEAN_PRIMARY_ROOT_INODE CLEAN_PRIMARY_ROOT_UID CLEAN_PRIMARY_ROOT_MODE \
    CLEAN_PRIMARY_DEVICE CLEAN_PRIMARY_INODE CLEAN_PRIMARY_UID CLEAN_PRIMARY_MODE CLEAN_PRIMARY_GIT_DEVICE CLEAN_PRIMARY_GIT_INODE CLEAN_PRIMARY_GIT_UID CLEAN_PRIMARY_GIT_MODE \
    CLEAN_PRIMARY_COMMON_DEVICE CLEAN_PRIMARY_COMMON_INODE CLEAN_PRIMARY_COMMON_UID CLEAN_PRIMARY_COMMON_MODE CLEAN_PRIMARY_OBJECTS_DEVICE CLEAN_PRIMARY_OBJECTS_INODE CLEAN_PRIMARY_OBJECTS_UID CLEAN_PRIMARY_OBJECTS_MODE <<< "$fields"
  CLEAN_PRIMARY_ROOT_REALPATH="$CLEAN_PRIMARY_ROOT"
  test "$CLEAN_PRIMARY_REALPATH" = "$CLEAN_PRIMARY" || fail "clean-primary canonical path was not bound"
  test "$CLEAN_PRIMARY_ROOT_REALPATH" = "$CLEAN_PRIMARY_ROOT" || fail "clean-primary root canonical path was not bound"
  CLEAN_PRIMARY_BOUND=1
  assert_clean_primary_identity
}

assert_clean_primary_storage_unshared() {
  "$PYTHON" - "$CLEAN_PRIMARY_OBJECTS" "$SOURCE_OBJECTS" <<'PY'
import os
import stat
import sys
objects, source_objects = sys.argv[1:]
objects = os.path.realpath(objects)
source_objects = os.path.realpath(source_objects)
if objects == source_objects or os.path.samefile(objects, source_objects):
    raise SystemExit('clean-primary object store shares SOURCE')
alternate = os.path.join(objects, 'info', 'alternates')
if os.path.lexists(alternate):
    raise SystemExit('clean-primary object store has objects/info/alternates')
regular_files = 0
for dirpath, dirnames, filenames in os.walk(objects, topdown=True, followlinks=False):
    dirnames[:] = sorted(dirnames)
    filenames.sort()
    for name in dirnames:
        path = os.path.join(dirpath, name)
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != path:
            raise SystemExit('clean-primary object-store directory is not canonical')
    for name in filenames:
        path = os.path.join(dirpath, name)
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or os.path.realpath(path) != path:
            raise SystemExit('clean-primary object-store file is not a canonical regular file')
        if st.st_nlink != 1:
            raise SystemExit('clean-primary object-store file has a shared hardlink')
        regular_files += 1
if regular_files == 0:
    raise SystemExit('clean-primary object store contains no regular object files')
PY
}

assert_clean_primary_identity() {
  test "$CLEAN_PRIMARY_ROOT_BOUND" -eq 1 && test "$CLEAN_PRIMARY_BOUND" -eq 1 || fail "clean-primary identity is incomplete"
  local git_dir common_dir objects
  git_dir="$(git_primary rev-parse --absolute-git-dir)"
  common_dir="$(git_primary rev-parse --git-common-dir)"
  objects="$(git_primary rev-parse --git-path objects)"
  "$PYTHON" - "$CLEAN_PRIMARY_ROOT" "$CLEAN_PRIMARY" "$git_dir" "$common_dir" "$objects" "$SOURCE_OBJECTS" "$SOURCE_GIT_COMMON_DIR" \
    "$CLEAN_PRIMARY_ROOT_DEVICE" "$CLEAN_PRIMARY_ROOT_INODE" "$CLEAN_PRIMARY_ROOT_UID" "$CLEAN_PRIMARY_ROOT_MODE" "$CLEAN_PRIMARY_ROOT_REALPATH" \
    "$CLEAN_PRIMARY_REALPATH" "$CLEAN_PRIMARY_DEVICE" "$CLEAN_PRIMARY_INODE" "$CLEAN_PRIMARY_UID" "$CLEAN_PRIMARY_MODE" \
    "$CLEAN_PRIMARY_GIT_DIR" "$CLEAN_PRIMARY_GIT_DEVICE" "$CLEAN_PRIMARY_GIT_INODE" "$CLEAN_PRIMARY_GIT_UID" "$CLEAN_PRIMARY_GIT_MODE" \
    "$CLEAN_PRIMARY_COMMON_DIR" "$CLEAN_PRIMARY_COMMON_DEVICE" "$CLEAN_PRIMARY_COMMON_INODE" "$CLEAN_PRIMARY_COMMON_UID" "$CLEAN_PRIMARY_COMMON_MODE" \
    "$CLEAN_PRIMARY_OBJECTS" "$CLEAN_PRIMARY_OBJECTS_DEVICE" "$CLEAN_PRIMARY_OBJECTS_INODE" "$CLEAN_PRIMARY_OBJECTS_UID" "$CLEAN_PRIMARY_OBJECTS_MODE" <<'PY'
import os
import stat
import sys
(root, repo, git_dir, common_dir, objects, source_objects, source_common, root_dev, root_ino, root_uid, root_mode, root_real, repo_real, repo_dev, repo_ino, repo_uid, repo_mode, git_real, git_dev, git_ino, git_uid, git_mode, common_real, common_dev, common_ino, common_uid, common_mode, objects_real, objects_dev, objects_ino, objects_uid, objects_mode) = sys.argv[1:]
def canonical(base, value):
    return os.path.realpath(value if os.path.isabs(value) else os.path.join(base, value))
def check(path, expected, wanted, label, required_mode=None):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != expected or expected != path:
        raise SystemExit(label + ' path changed')
    actual = [str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')]
    if actual != wanted:
        raise SystemExit(label + ' lstat identity changed')
    if required_mode is not None and stat.S_IMODE(st.st_mode) != required_mode:
        raise SystemExit(label + ' mode changed')
check(root, root_real, [root_dev, root_ino, root_uid, root_mode], 'clean-primary root', 0o700)
check(repo, repo_real, [repo_dev, repo_ino, repo_uid, repo_mode], 'clean-primary repository')
if repo == root or os.path.commonpath([repo, root]) != root:
    raise SystemExit('clean-primary repository escaped its root')
check(canonical(repo, git_dir), git_real, [git_dev, git_ino, git_uid, git_mode], 'clean-primary Git directory')
check(canonical(repo, common_dir), common_real, [common_dev, common_ino, common_uid, common_mode], 'clean-primary common directory')
check(canonical(repo, objects), objects_real, [objects_dev, objects_ino, objects_uid, objects_mode], 'clean-primary object store')
if os.path.lexists(os.path.join(objects_real, 'info', 'alternates')):
    raise SystemExit('clean-primary alternates appeared')
if os.path.samefile(objects_real, source_objects) or os.path.samefile(common_real, source_common):
    raise SystemExit('clean-primary storage became shared with SOURCE')
PY
  assert_clean_primary_storage_unshared
}

assert_clean_primary_state() {
  assert_source_binding
  assert_clean_primary_identity
  test "$(git_primary rev-parse --show-toplevel)" = "$CLEAN_PRIMARY" || fail "clean-primary top-level changed"
  test "$(git_primary rev-parse origin/dev)" = "$BASE" || fail "clean-primary origin/dev drifted"
  test "$(git_primary rev-parse origin/main)" = "$MAIN" || fail "clean-primary origin/main drifted"
  if git_primary symbolic-ref -q HEAD >/dev/null 2>&1; then fail "clean-primary HEAD is attached"; fi
  test "$(git_primary rev-parse HEAD)" = "$BASE" || fail "clean-primary HEAD drifted"
  test "$(git_primary rev-parse HEAD^{tree})" = "$BASE_TREE" || fail "clean-primary tree drifted"
  local whole_worktree_status
  whole_worktree_status="$(git_primary status --porcelain=v1 --untracked-files=all --ignored=traditional --ignore-submodules=none)"
  test -z "$whole_worktree_status" || fail "clean-primary whole worktree is not clean, including ignored/untracked files"
  test -z "$(git_primary ls-files --others --ignored --exclude-standard -z)" || fail "clean-primary has ignored descendants"
  git_primary diff --no-ext-diff --quiet
  git_primary diff --cached --no-ext-diff --quiet
}

before_clean_primary_mutation() {
  assert_root_shape
  assert_source_binding
  assert_worktree_separation
  if [ "$CLEAN_PRIMARY_BOUND" -eq 1 ]; then
    assert_clean_primary_identity
    assert_clean_primary_storage_unshared
  fi
}

assert_clean_primary_adversarial_smoke() {
  [ "$CLEAN_PRIMARY_SMOKE_DONE" -eq 0 ] || return 0
  "$PYTHON" <<'PY'
import os
import shutil
import stat
import tempfile
root = tempfile.mkdtemp(prefix='task409-clean-primary-smoke.', dir='/tmp')
def identity(path):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != path:
        raise RuntimeError('identity rejected')
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), path)
def require_reject(label, fn):
    try:
        result = fn()
    except Exception:
        return
    if result is False:
        return
    raise RuntimeError('smoke accepted '+label)
def storage_check(source, clean, repository):
    if os.path.lexists(os.path.join(clean, 'info', 'alternates')):
        raise RuntimeError('alternate accepted')
    if os.path.samefile(source, clean):
        raise RuntimeError('shared store accepted')
    if os.path.realpath(repository) == os.path.realpath(clean):
        raise RuntimeError('repository identity accepted')
def no_shared_hardlinks(objects):
    count = 0
    for dirpath, dirnames, filenames in os.walk(objects, topdown=True, followlinks=False):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) or st.st_nlink != 1:
                return False
            if stat.S_ISREG(st.st_mode):
                count += 1
    return count > 0
try:
    preexisting = os.path.join(root, 'preexisting')
    os.mkdir(preexisting, 0o700)
    require_reject('preexisting path', lambda: os.mkdir(preexisting, 0o700))
    bound = os.path.join(root, 'bound')
    os.mkdir(bound, 0o700)
    expected = identity(bound)
    os.rename(bound, bound+'.real')
    os.symlink(bound+'.real', bound)
    require_reject('symlink substitution', lambda: identity(bound) == expected)
    os.unlink(bound)
    os.rename(bound+'.real', bound)
    source = os.path.join(root, 'source-objects')
    clean = os.path.join(root, 'clean-objects')
    repository = os.path.join(root, 'repository')
    os.mkdir(source, 0o700); os.mkdir(clean, 0o700); os.mkdir(repository, 0o700); os.mkdir(os.path.join(clean, 'info'), 0o700)
    alternate = os.path.join(clean, 'info', 'alternates')
    with open(alternate, 'w'):
        pass
    require_reject('alternates', lambda: storage_check(source, clean, repository))
    os.unlink(alternate)
    hardlink_store = os.path.join(root, 'hardlink-objects')
    os.mkdir(hardlink_store, 0o700)
    pack_dir = os.path.join(hardlink_store, 'pack')
    os.mkdir(pack_dir, 0o700)
    loose = os.path.join(hardlink_store, 'aa-loose-object')
    pack = os.path.join(pack_dir, 'sample.pack')
    index = os.path.join(pack_dir, 'sample.idx')
    for path in (loose, pack, index):
        with open(path, 'wb') as handle:
            handle.write(b'x')
        os.link(path, path + '.shared')
    require_reject('shared hardlinked object/pack/index file', lambda: no_shared_hardlinks(hardlink_store))
    shutil.rmtree(hardlink_store)
    shutil.rmtree(clean)
    os.symlink(source, clean)
    require_reject('shared object store', lambda: storage_check(source, clean, repository))
    os.unlink(clean); os.mkdir(clean, 0o700); os.mkdir(os.path.join(clean, 'info'), 0o700)
    bound_refs = {'dev': 'exact-dev', 'main': 'exact-main', 'tree': 'exact-tree'}
    source_refs = dict(bound_refs); source_refs['dev'] = 'drifted-dev'
    require_reject('source/ref drift', lambda: source_refs == bound_refs)
    clean_status = ['?? unknown']
    require_reject('dirty clean-primary', lambda: not clean_status)
    ignored_status = ['!! ignored']
    require_reject('ignored clean-primary artifact', lambda: not ignored_status)
    swapped = os.path.join(root, 'inode-swap')
    os.mkdir(swapped, 0o700); old = identity(swapped); os.rename(swapped, swapped+'.old'); os.mkdir(swapped, 0o700)
    require_reject('inode swap', lambda: identity(swapped) == old)
    os.chmod(swapped, 0o755); mode_bound = identity(swapped); os.chmod(swapped, 0o700)
    require_reject('mode swap', lambda: identity(swapped) == mode_bound)
    cleanup = os.path.join(root, 'cleanup'); os.mkdir(cleanup, 0o700); os.mkdir(os.path.join(cleanup, 'repository'), 0o700)
    with open(os.path.join(cleanup, 'unknown'), 'w'):
        pass
    require_reject('unknown cleanup artifact', lambda: set(os.listdir(cleanup)) == {'repository'})
finally:
    shutil.rmtree(root)
PY
  CLEAN_PRIMARY_SMOKE_DONE=1
}

bootstrap_clean_primary() {
  create_clean_primary_root
  before_clean_primary_mutation
  assert_source_binding
  assert_root_shape
  # The repository child was created through the held root descriptor. Git CLI
  # still accepts a pathname, so assert parent/root/child immediately before and after it.
  # --no-hardlinks copies objects into a distinct local object store; no network or mutable alternate is used.
  git_hermetic -c protocol.file.allow=always clone --no-local --no-hardlinks --no-checkout --no-tags "$SOURCE" "$CLEAN_PRIMARY" >/dev/null
  bind_clean_primary_identity
  assert_root_shape
  assert_worktree_separation
  before_clean_primary_mutation
  git_primary config --local core.hooksPath /dev/null
  before_clean_primary_mutation
  git_primary config --local protocol.allow never
  before_clean_primary_mutation
  git_primary config --local remote.origin.url "$SOURCE"
  before_clean_primary_mutation
  git_primary config --local remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'
  before_clean_primary_mutation
  git_primary update-ref --no-deref refs/remotes/origin/dev "$BASE"
  before_clean_primary_mutation
  git_primary update-ref --no-deref refs/remotes/origin/main "$MAIN"
  before_clean_primary_mutation
  git_primary update-ref --no-deref HEAD "$BASE"
  before_clean_primary_mutation
  assert_root_shape
  assert_worktree_separation
  git_primary checkout --detach --force "$BASE" >/dev/null
  assert_root_shape
  assert_worktree_separation
  assert_clean_primary_state
}

create_replay_root() {
  test "${REPLAY_ROOT_BOUND}" -eq 0 || fail "create replay root already bound"
  assert_root_shape
  assert_worktree_separation
  local identity
  identity="$($PYTHON - "create replay root" "${REPLAY_ROOT}" "${REPLAY}" "$SOURCE" "$CLEAN_PRIMARY" "$CLEAN_PRIMARY_BOUND" <<'PY'

import os
import stat
import subprocess
import sys

label, root, child, source, clean, clean_bound = sys.argv[1:]
root = os.path.abspath(root)
child = os.path.abspath(child)
source = os.path.abspath(source)
clean = os.path.abspath(clean)
if os.path.realpath(root) != root or os.path.realpath(child) != child:
    raise SystemExit(f'{label} root/child path is not canonical')
if os.path.dirname(child) != root or os.path.basename(child) not in ('repository', 'replay'):
    raise SystemExit(f'{label} child is not an exact root child')
parent = os.path.dirname(root)
if os.path.realpath(parent) != parent:
    raise SystemExit(f'{label} parent is not canonical')

ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}

def identity(st):
    return (str(st.st_dev), str(st.st_ino), str(st.st_uid),
            format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink))

def occupied(raw, repo, owner):
    if not isinstance(raw, str) or not raw or '\x00' in raw:
        raise SystemExit(f'{owner} registry has a malformed empty worktree path')
    absolute = raw if os.path.isabs(raw) else os.path.abspath(os.path.join(repo, raw))
    forms = tuple(dict.fromkeys((raw, absolute, os.path.normpath(absolute), os.path.realpath(absolute))))
    try:
        st = os.lstat(absolute)
    except FileNotFoundError:
        # Stale/prunable paths remain lexical occupancy evidence. They do not
        # need an lstat identity until they exist again.
        return forms, ('missing',)
    except OSError as exc:
        raise SystemExit(f'{owner} registered worktree lstat failed: {raw}: {exc}')
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(absolute) != absolute:
        raise SystemExit(f'{owner} registered worktree is not a canonical real directory: {raw}')
    return forms, ('present', *identity(st))

def parse_registry(output, owner, repo):
    # Each porcelain block must contain exactly one non-empty worktree path.
    # Locked, prunable, duplicate, and stale records are retained; malformed
    # blocks fail closed rather than becoming an unoccupied empty record.
    records = []
    block = []
    def finish(lines):
        if not lines:
            return
        paths = [line[9:] for line in lines if line.startswith('worktree ')]
        if any(line == 'worktree' for line in lines) or len(paths) != 1 or not paths[0]:
            raise SystemExit(f'{owner} registry block is malformed or ambiguous')
        raw = paths[0]
        forms, state = occupied(raw, repo, owner)
        records.append((raw, forms, state, tuple(lines)))
    for line in output.splitlines():
        if line == '':
            finish(block)
            block = []
        else:
            block.append(line)
    finish(block)
    return tuple(records)

def registry_snapshot():
    repos = [('source', source)]
    if clean_bound == '1':
        repos.append(('clean-primary', clean))
    rows = []
    for owner, repo in repos:
        output = subprocess.check_output([
            '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks',
            '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-c', 'protocol.allow=never',
            'worktree', 'list', '--porcelain',
        ], env=ENV, text=True)
        rows.append((owner, output, parse_registry(output, owner, repo)))
    return tuple(rows)

def overlap(a, b):
    if a == b:
        return True
    if not os.path.isabs(a) or not os.path.isabs(b):
        return False
    try:
        return os.path.commonpath([a, b]) in (a, b)
    except ValueError:
        return False

def validate_registry(rows, candidate):
    candidate_forms = (candidate, os.path.realpath(candidate))
    for owner, _output, records in rows:
        repo = source if owner == 'source' else clean
        own_forms, _own_state = occupied(repo, repo, owner)
        own_forms = set(own_forms)
        for raw, entry_forms, _state, _lines in records:
            if set(entry_forms) & own_forms:
                continue
            if any(overlap(item, target) for item in entry_forms for target in candidate_forms):
                raise SystemExit(f'registered/nested worktree overlaps {candidate}: {raw}')

before_registry = registry_snapshot()
validate_registry(before_registry, root)
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    parent_before = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_before.st_mode) or os.path.realpath(parent) != parent:
        raise SystemExit(f'{label} parent descriptor is unsafe')
    name = os.path.basename(root)
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise SystemExit(f'{label} root already exists')
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    root_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        root_first = os.fstat(root_fd)
        if not stat.S_ISDIR(root_first.st_mode) or stat.S_IMODE(root_first.st_mode) != 0o700:
            raise SystemExit(f'{label} root descriptor is unsafe')
        os.mkdir(os.path.basename(child), 0o700, dir_fd=root_fd)
        child_fd = os.open(os.path.basename(child), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            child_stat = os.fstat(child_fd)
            if not stat.S_ISDIR(child_stat.st_mode) or stat.S_IMODE(child_stat.st_mode) != 0o700:
                raise SystemExit(f'{label} child descriptor is unsafe')
            root_after = os.fstat(root_fd)
            parent_after = os.fstat(parent_fd)
            root_final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            child_final = os.stat(os.path.basename(child), dir_fd=root_fd, follow_symlinks=False)
            os.fsync(root_fd)
            os.fsync(parent_fd)
        finally:
            os.close(child_fd)
    finally:
        os.close(root_fd)
finally:
    os.close(parent_fd)

def ident(st):
    return (str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink))
if ident(parent_before) != ident(parent_after):
    raise SystemExit(f'{label} parent changed during root/child creation')
if ident(root_after) != ident(root_final) or ident(child_stat) != ident(child_final):
    raise SystemExit(f'{label} root/child final identity changed during creation')
after_registry = registry_snapshot()
if after_registry != before_registry:
    raise SystemExit(f'{label} registered worktree registry changed during root/child creation')
if os.path.realpath(root) != root or os.path.realpath(child) != child:
    raise SystemExit(f'{label} root/child became noncanonical')
print('\t'.join([root, *ident(parent_after), *ident(root_after), child, *ident(child_final)]))

PY
)"
  IFS=$'\t' read -r \
    REPLAY_ROOT_REALPATH \
    REPLAY_PARENT_DEVICE REPLAY_PARENT_INODE REPLAY_PARENT_UID REPLAY_PARENT_MODE REPLAY_PARENT_NLINK \
    REPLAY_ROOT_DEVICE REPLAY_ROOT_INODE REPLAY_ROOT_UID REPLAY_ROOT_MODE REPLAY_ROOT_NLINK \
    REPLAY_CHECKOUT_REALPATH REPLAY_CHECKOUT_DEVICE REPLAY_CHECKOUT_INODE REPLAY_CHECKOUT_UID REPLAY_CHECKOUT_MODE REPLAY_CHECKOUT_NLINK <<< "$identity"
  test "${REPLAY_ROOT_REALPATH}" = "${REPLAY_ROOT}" || fail "create replay root canonical binding failed"
  test "${REPLAY_CHECKOUT_REALPATH}" = "${REPLAY}" || fail "create replay root child canonical binding failed"
  REPLAY_ROOT_BOUND=1
  REPLAY_CHECKOUT_BOUND=1
  REPLAY_CHECKOUT_PRESENT=1
  assert_root_shape
  assert_worktree_separation
}




bind_matrix_snapshot() {
  test "$REPLAY_ROOT_BOUND" -eq 1 || fail "matrix snapshot requires a bound replay root"
  test "$MATRIX_BOUND" -eq 0 || fail "matrix snapshot was already bound"
  local identity
  identity="$("$PYTHON" - "$MATRIX_SOURCE" "$MATRIX_SNAPSHOT" "$MATRIX_EXPECTED_BINDING_SHA256" <<'PY'
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import hashlib
import json
import os
import re
import stat
import sys
source, snapshot, expected = sys.argv[1:]
if not hasattr(os, 'O_NOFOLLOW'):
    raise SystemExit('secure no-follow support is unavailable')
if not re.fullmatch(r'[0-9a-f]{64}', expected):
    raise SystemExit('matrix identity token is not a SHA-256 value')
def normalized_sha(raw):
    normalized = raw.replace(expected.encode('ascii'), b'0' * 64)
    for key in (b'"shell_sha256": "', b'"driver_shell_sha256": "', b'"expected_body_sha256": "'):
        normalized = re.sub(re.escape(key) + rb'[0-9a-f]{64}(?=")', lambda match: match.group(0)[:len(key)] + b'0' * 64, normalized)
    return hashlib.sha256(normalized).hexdigest()
raw, source_stat = read_stable_file(source, 'matrix source')
if normalized_sha(raw) != expected:
    raise SystemExit('matrix source normalized SHA-256 mismatch')
try:
    json.loads(raw.decode('utf-8'))
except Exception as exc:
    raise SystemExit(f'matrix source JSON parse failed: {exc}')
try:
    snapshot_fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
except FileExistsError:
    raise SystemExit(f'matrix snapshot already exists: {snapshot}')
try:
    view = memoryview(raw)
    written = 0
    while written < len(raw):
        written += os.write(snapshot_fd, view[written:])
    os.fsync(snapshot_fd)
finally:
    os.close(snapshot_fd)
snapshot_stat = os.lstat(snapshot)
if stat.S_ISLNK(snapshot_stat.st_mode) or not stat.S_ISREG(snapshot_stat.st_mode):
    raise SystemExit('matrix snapshot is not a regular file')
if stat.S_IMODE(snapshot_stat.st_mode) != 0o600:
    raise SystemExit('matrix snapshot mode is not 0600')
if snapshot_stat.st_size != len(raw):
    raise SystemExit('matrix snapshot size mismatch after write')
if os.path.realpath(snapshot) != snapshot:
    raise SystemExit('matrix snapshot canonical path changed')
reread, reread_stat = read_stable_file(snapshot, 'matrix snapshot')
if reread != raw:
    raise SystemExit('matrix snapshot bytes differ from the single source read')
if (reread_stat.st_dev, reread_stat.st_ino, reread_stat.st_size) != (snapshot_stat.st_dev, snapshot_stat.st_ino, snapshot_stat.st_size):
    raise SystemExit('matrix snapshot descriptor identity changed')
if normalized_sha(reread) != expected:
    raise SystemExit('matrix snapshot normalized SHA-256 mismatch after reopen')
print(f'{snapshot_stat.st_dev}\t{snapshot_stat.st_ino}\t{snapshot_stat.st_size}\t{os.path.realpath(snapshot)}')
PY
)"
  IFS=$'\t' read -r MATRIX_SNAPSHOT_DEVICE MATRIX_SNAPSHOT_INODE MATRIX_SNAPSHOT_SIZE MATRIX_SNAPSHOT_REALPATH <<< "$identity"
  test -n "$MATRIX_SNAPSHOT_DEVICE" && test -n "$MATRIX_SNAPSHOT_INODE" && test -n "$MATRIX_SNAPSHOT_SIZE" || fail "matrix snapshot identity was not captured"
  test "$MATRIX_SNAPSHOT_REALPATH" = "$MATRIX_SNAPSHOT" || fail "matrix snapshot canonical identity was not captured"
  MATRIX="$MATRIX_SNAPSHOT"
  MATRIX_BOUND=1
  assert_matrix_identity
}

assert_bash32_array_smoke() {
  [ "$BASH_ARRAY_SMOKE_DONE" -eq 0 ] || return 0
  # Save and restore only when the declared array has elements. Bash 3.2 nounset
  # rejects an empty/unset indexed-array expansion even when it is quoted.
  local saved_dirty=() item count saved_count
  saved_count=${#DIRTY_PATHS[@]}
  if [ "$saved_count" -gt 0 ]; then
    saved_dirty=("${DIRTY_PATHS[@]}")
  fi
  DIRTY_PATHS=()
  count=0
  if [ "${#DIRTY_PATHS[@]}" -gt 0 ]; then
    for item in "${DIRTY_PATHS[@]}"; do
      count=$((count + 1))
    done
  fi
  test "$count" -eq 0 || fail "empty DIRTY_PATHS smoke case yielded an element"
  test "${#DIRTY_PATHS[@]}" -eq 0 || fail "empty DIRTY_PATHS smoke length changed"
  add_dirty_path 'task409-smoke/one path'
  test "${#DIRTY_PATHS[@]}" -eq 1 || fail "single DIRTY_PATHS smoke path was not added"
  add_dirty_path 'task409-smoke/one path'
  test "${#DIRTY_PATHS[@]}" -eq 1 || fail "duplicate DIRTY_PATHS smoke path was added twice"
  DIRTY_PATHS=('task409-smoke/one path' 'task409-smoke/two')
  count=0
  if [ "${#DIRTY_PATHS[@]}" -gt 0 ]; then
    for item in "${DIRTY_PATHS[@]}"; do
      case "$item" in
        'task409-smoke/one path'|'task409-smoke/two') count=$((count + 1)) ;;
        *) fail "non-empty DIRTY_PATHS smoke path was altered: $item" ;;
      esac
    done
  fi
  test "$count" -eq 2 || fail "non-empty DIRTY_PATHS smoke case lost a path"
  DIRTY_PATHS=()
  if [ "${#saved_dirty[@]}" -gt 0 ]; then
    DIRTY_PATHS=("${saved_dirty[@]}")
  fi
  test "${#DIRTY_PATHS[@]}" -eq "$saved_count" || fail "DIRTY_PATHS smoke save/restore cardinality changed"
  BASH_ARRAY_SMOKE_DONE=1
}

assert_replay_closure() {
  # Closure is checked after replay bootstrap and again immediately before
  # cleanup. The replay alternate is intentional, but only its exact bound
  # clean-primary object store is allowed; HTTP, replacement, promisor, partial,
  # helper, shallow, and graft metadata remain forbidden.
  "$PYTHON" - "$REPLAY" "$CLEAN_PRIMARY_OBJECTS" "$MATRIX" "$CURRENT_HEAD" <<'PY'
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

repo, clean_objects, matrix, expected_head = sys.argv[1:]
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
    'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
    'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
    'GIT_NO_LAZY_FETCH': '1',
}

def run(*args, check=True):
    command = [
        '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch',
        '--no-optional-locks', '-C', repo,
        '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
        *args,
    ]
    process = subprocess.run(
        command, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if check and process.returncode:
        raise SystemExit(f'Git replay closure command failed: {args!r}')
    return process

def out(*args):
    process = run(*args)
    return process.stdout.decode('utf-8', errors='strict').strip()

def identity(st):
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

def require_regular(path, label):
    st = os.lstat(path)
    if (stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1 or os.path.realpath(path) != path):
        raise SystemExit(f'{label} is not a canonical regular single-link file')
    return st

if out('rev-parse', '--show-object-format') != 'sha1':
    raise SystemExit('replay repository object format is not SHA-1')
if out('rev-parse', '--is-shallow-repository') != 'false':
    raise SystemExit('replay repository is shallow')
if expected_head and out('rev-parse', 'HEAD') != expected_head:
    raise SystemExit('replay HEAD changed during closure check')
repo = os.path.realpath(repo)
git_dir = os.path.realpath(out('rev-parse', '--absolute-git-dir'))
if git_dir != os.path.join(repo, '.git'):
    raise SystemExit('replay Git directory is external or noncanonical')
common_dir = out('rev-parse', '--git-common-dir')
common_dir = os.path.realpath(common_dir if os.path.isabs(common_dir) else os.path.join(repo, common_dir))
if common_dir != git_dir or os.path.lexists(os.path.join(git_dir, 'commondir')):
    raise SystemExit('replay common directory is external or indirect')
objects = os.path.realpath(out('rev-parse', '--git-path', 'objects'))
if objects != os.path.join(git_dir, 'objects'):
    raise SystemExit('replay object store is external or noncanonical')
for path in (
    os.path.join(git_dir, 'shallow'),
    os.path.join(git_dir, 'info', 'grafts'),
    os.path.join(git_dir, 'refs', 'replace'),
    os.path.join(objects, 'info', 'http-alternates'),
):
    if os.path.lexists(path):
        raise SystemExit(f'forbidden replay metadata exists: {path}')
packed_refs = os.path.join(git_dir, 'packed-refs')
if os.path.lexists(packed_refs):
    packed_st = require_regular(packed_refs, 'replay packed-refs')
    if b'refs/replace/' in Path(packed_refs).read_bytes():
        raise SystemExit('packed replacement refs are forbidden')
pack_dir = os.path.join(objects, 'pack')
if os.path.lexists(pack_dir) and (os.path.islink(pack_dir)
        or not os.path.isdir(pack_dir) or os.path.realpath(pack_dir) != pack_dir):
    raise SystemExit('replay pack directory is not canonical')
if os.path.isdir(pack_dir):
    for directory, names, files in os.walk(pack_dir, topdown=True, followlinks=False):
        names[:] = sorted(names)
        files.sort()
        if any(os.path.islink(os.path.join(directory, name)) for name in names):
            raise SystemExit('replay pack directory contains a symlink')
        if any(name.endswith('.promisor') for name in files):
            raise SystemExit('replay promisor pack metadata is forbidden')

alternate = os.path.join(objects, 'info', 'alternates')
alt_st = require_regular(alternate, 'replay alternates')
fd = os.open(alternate, os.O_RDONLY | os.O_NOFOLLOW)
try:
    first = os.fstat(fd)
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    second = os.fstat(fd)
finally:
    os.close(fd)
final = os.stat(alternate, follow_symlinks=False)
if identity(first) != identity(second) or identity(first) != identity(final):
    raise SystemExit('replay alternates changed during closure check')
expected_alternate = (os.path.realpath(clean_objects) + '\n').encode('utf-8')
if b''.join(chunks) != expected_alternate:
    raise SystemExit('replay alternates are not the exact clean-primary object store')

config = run(
    'config', '--local', '--get-regexp',
    r'^(extensions\.partialClone|remote\..*|protocol\..*\.allow)$',
    check=False,
)
for line in config.stdout.decode('utf-8', errors='strict').splitlines():
    key, _, value = line.partition(' ')
    lowered = key.lower()
    if lowered == 'extensions.partialclone' or lowered.startswith('remote.'):
        raise SystemExit('partial-clone, promisor, remote-helper, or remote transport configuration is forbidden')
    if lowered.startswith('protocol.') and value.strip().lower() not in ('never', ''):
        raise SystemExit('unsafe protocol transport policy is forbidden')

fsck = run('fsck', '--full', '--strict', '--no-reflogs', '--no-progress', check=False)
if fsck.returncode != 0:
    raise SystemExit('strict replay fsck failed')
missing = run('rev-list', '--objects', '--all', '--missing=error', check=False)
if missing.returncode != 0:
    raise SystemExit('replay object closure is incomplete')

expected_by_key = {
    'commit': 'commit', 'parent': 'commit', 'parents': 'commit',
    'child': 'commit', 'tree': 'tree', 'blob': 'blob',
}
object_ids = {}
def collect(node, key=None):
    if isinstance(node, dict):
        for child_key, child in node.items():
            collect(child, child_key)
    elif isinstance(node, list):
        for child in node:
            collect(child, key)
    elif isinstance(node, str) and re.fullmatch(r'[0-9a-f]{40}', node) and key in expected_by_key:
        object_ids[node] = expected_by_key[key]

data = json.loads(Path(matrix).read_bytes())
collect(data)
for object_id, expected_type in sorted(object_ids.items()):
    actual = out('cat-file', '-t', object_id)
    if actual != expected_type:
        raise SystemExit(f'explicit replay object type mismatch: {object_id}: {actual} != {expected_type}')
PY
}

assert_tools() {
  for tool in "$GIT" "$PYTHON" "$BASH" "$ENV" "$MKDIR" "$RM" "$RMDIR" "$CUT" "$SHASUM"; do
    test -x "$tool" || fail "trusted executable unavailable: $tool"
  done
  test "$(git_hermetic --version | "$CUT" -d' ' -f1)" = git || fail "unexpected Git executable"
  local bash_version
  bash_version="$("$BASH" -c 'printf "%s" "$BASH_VERSION"')"
  case "$bash_version" in 3.2.*|4.*|5.*) ;; *) fail "unsupported trusted Bash version: $bash_version" ;; esac
  assert_bash32_array_smoke
  assert_clean_primary_adversarial_smoke
}


assert_root_shape() {
  case "$CLEAN_PRIMARY_ROOT" in /tmp/hermternal-task409-final-clean-primary.[0-9]*) ;; *) fail "invalid clean-primary root: $CLEAN_PRIMARY_ROOT" ;; esac
  case "$REPLAY_ROOT" in /tmp/hermternal-task409-final-replay.[0-9]*) ;; *) fail "invalid replay root: $REPLAY_ROOT" ;; esac
  test "$CLEAN_PRIMARY" = "$CLEAN_PRIMARY_ROOT/repository" || fail "clean-primary repository escaped its root"
  test "$REPLAY" = "$REPLAY_ROOT/replay" || fail "replay checkout escaped its root"
  "$PYTHON" - "$SOURCE" "$CLEAN_PRIMARY_ROOT" "$CLEAN_PRIMARY" "$REPLAY_ROOT" "$REPLAY" "$CLEAN_PRIMARY_ROOT_BOUND" "$CLEAN_PRIMARY_REPOSITORY_BOUND" "$CLEAN_PRIMARY_BOUND" "$REPLAY_ROOT_BOUND" "$REPLAY_CHECKOUT_BOUND" "$REPLAY_CHECKOUT_PRESENT" "$REPLAY_GIT_BOUND" "$CLEAN_PRIMARY_PARENT_DEVICE" "$CLEAN_PRIMARY_PARENT_INODE" "$CLEAN_PRIMARY_PARENT_UID" "$CLEAN_PRIMARY_PARENT_MODE" "$CLEAN_PRIMARY_PARENT_NLINK" "$CLEAN_PRIMARY_ROOT_DEVICE" "$CLEAN_PRIMARY_ROOT_INODE" "$CLEAN_PRIMARY_ROOT_UID" "$CLEAN_PRIMARY_ROOT_MODE" "$CLEAN_PRIMARY_ROOT_NLINK" "$CLEAN_PRIMARY_ROOT_REALPATH" "$CLEAN_PRIMARY_REPOSITORY_DEVICE" "$CLEAN_PRIMARY_REPOSITORY_INODE" "$CLEAN_PRIMARY_REPOSITORY_UID" "$CLEAN_PRIMARY_REPOSITORY_MODE" "$CLEAN_PRIMARY_REPOSITORY_NLINK" "$REPLAY_PARENT_DEVICE" "$REPLAY_PARENT_INODE" "$REPLAY_PARENT_UID" "$REPLAY_PARENT_MODE" "$REPLAY_PARENT_NLINK" "$REPLAY_ROOT_DEVICE" "$REPLAY_ROOT_INODE" "$REPLAY_ROOT_UID" "$REPLAY_ROOT_MODE" "$REPLAY_ROOT_NLINK" "$REPLAY_ROOT_REALPATH" "$REPLAY_CHECKOUT_DEVICE" "$REPLAY_CHECKOUT_INODE" "$REPLAY_CHECKOUT_UID" "$REPLAY_CHECKOUT_MODE" "$REPLAY_CHECKOUT_NLINK" <<'PY'
import os
import stat
import sys
(values) = sys.argv[1:]
(source, clean_root, clean_repo, replay_root, replay_repo, clean_root_bound, clean_child_bound, clean_bound, replay_root_bound, replay_child_bound, replay_child_present, replay_git_bound, *rest) = values
idx = 0
def take(n):
    global idx
    value = rest[idx:idx+n]; idx += n
    return value
clean_parent = take(5); clean_root_id = take(5); clean_child = take(5)
replay_parent = take(5); replay_root_id = take(5); replay_child = take(5)
def overlaps(a, b):
    try:
        return a == b or os.path.commonpath([a, b]) in (a, b)
    except ValueError:
        return False
def verify(path, expected, wanted, label, required_mode=None, allow_nlink_growth=True):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != expected or expected != path:
        raise SystemExit(label + ' path changed')
    actual = [str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink)]
    if actual[:4] != wanted[:4] or (not allow_nlink_growth and actual[4] != wanted[4]) or (allow_nlink_growth and int(actual[4]) < int(wanted[4])):
        raise SystemExit(label + ' identity changed')
    if required_mode is not None and stat.S_IMODE(st.st_mode) != required_mode:
        raise SystemExit(label + ' mode changed')
def verify_parent(path, wanted, label):
    verify(path, path, wanted, label, allow_nlink_growth=True)
source_real = os.path.realpath(source)
if source_real != source:
    raise SystemExit('SOURCE path is not canonical')
for candidate, label in ((clean_root, 'clean-primary'), (replay_root, 'replay')):
    parent = os.path.dirname(candidate)
    parent_st = os.lstat(parent)
    if stat.S_ISLNK(parent_st.st_mode) or not stat.S_ISDIR(parent_st.st_mode) or os.path.realpath(parent) != parent:
        raise SystemExit(label + ' parent is not canonical')
if clean_root_bound == '0':
    if os.path.lexists(clean_root) or os.path.lexists(clean_repo):
        raise SystemExit('unbound clean-primary path exists')
else:
    verify_parent(os.path.dirname(clean_root), clean_parent, 'clean-primary parent')
    verify(clean_root, clean_root, clean_root_id, 'clean-primary root', 0o700)
    if clean_child_bound != '1':
        raise SystemExit('clean-primary root is bound without its child descriptor')
    verify(clean_repo, clean_repo, clean_child, 'clean-primary repository')
if replay_root_bound == '0':
    if os.path.lexists(replay_root) or os.path.lexists(replay_repo):
        raise SystemExit('unbound replay root exists')
else:
    verify_parent(os.path.dirname(replay_root), replay_parent, 'replay parent')
    verify(replay_root, replay_root, replay_root_id, 'replay root', 0o700)
    if replay_child_present == '0':
        if os.path.lexists(replay_repo):
            raise SystemExit('removed replay checkout still exists')
    else:
        if replay_child_bound != '1':
            raise SystemExit('replay root is present without its child descriptor')
        verify(replay_repo, replay_repo, replay_child, 'replay checkout')
clean_real = os.path.realpath(clean_root)
replay_real = os.path.realpath(replay_root)
if overlaps(source_real, clean_real) or overlaps(source_real, replay_real) or overlaps(clean_real, replay_real):
    raise SystemExit('repository/root paths overlap')
PY
}


assert_matrix_identity() {
  if [ "$MATRIX_BOUND" -eq 0 ]; then
    test "$MATRIX" = "$MATRIX_SOURCE" || fail "unbound matrix path changed"
    test "$MATRIX_SOURCE_VALIDATED" -eq 1 || fail "matrix source was not validated before root creation"
    return 0
  fi
  test "$MATRIX_BOUND" -eq 1 || fail "invalid matrix binding state"
  test "$MATRIX" = "$MATRIX_SNAPSHOT" || fail "matrix path escaped immutable snapshot"
  "$PYTHON" - "$MATRIX" "$MATRIX_EXPECTED_BINDING_SHA256" "$MATRIX_SNAPSHOT_DEVICE" "$MATRIX_SNAPSHOT_INODE" "$MATRIX_SNAPSHOT_SIZE" "$MATRIX_SNAPSHOT_REALPATH" <<'PY'
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import hashlib
import json
import os
import re
import stat
import sys
path, expected, expected_device, expected_inode, expected_size, expected_realpath = sys.argv[1:]
if not hasattr(os, 'O_NOFOLLOW'):
    raise SystemExit('secure no-follow open is unavailable')
if not re.fullmatch(r'[0-9a-f]{64}', expected):
    raise SystemExit('matrix identity token is not a SHA-256 value')
raw, first = read_stable_file(path, 'matrix snapshot')
path_stat = os.lstat(path)
if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
    raise SystemExit('matrix snapshot path is not a regular non-symlink file')
if (path_stat.st_dev, path_stat.st_ino, path_stat.st_size) != (first.st_dev, first.st_ino, first.st_size):
    raise SystemExit('matrix snapshot path identity changed')
if (str(first.st_dev), str(first.st_ino), str(first.st_size)) != (expected_device, expected_inode, expected_size):
    raise SystemExit('matrix snapshot device/inode/size binding changed')
if os.path.realpath(path) != expected_realpath or expected_realpath != path:
    raise SystemExit('matrix snapshot canonical path changed')
token = expected.encode('ascii')
normalized = raw.replace(token, b'0' * 64)
for key in (b'"shell_sha256": "', b'"driver_shell_sha256": "', b'"expected_body_sha256": "'):
    normalized = re.sub(re.escape(key) + rb'[0-9a-f]{64}(?=")', lambda match: match.group(0)[:len(key)] + b'0' * 64, normalized)
if hashlib.sha256(normalized).hexdigest() != expected:
    raise SystemExit('matrix snapshot normalized SHA-256 mismatch')
try:
    json.loads(raw.decode('utf-8'))
except Exception as exc:
    raise SystemExit(f'matrix snapshot JSON parse failed: {exc}')
PY
}


assert_worktree_separation() {
  # Git has no compatible advisory lock for its common-dir worktree registry.
  # Therefore each scan is operation-adjacent and fails closed on registry/root
  # changes; stale unrelated records are retained as occupancy evidence and are
  # ignored only after raw and canonical forms prove no candidate overlap.
  "$PYTHON" - "$SOURCE" "$CLEAN_PRIMARY" "$REPLAY" "$CLEAN_PRIMARY_ROOT" "$REPLAY_ROOT" "$CLEAN_PRIMARY_BOUND" "$REPLAY_ROOT_BOUND" "$CLEAN_PRIMARY_REPOSITORY_BOUND" "$REPLAY_CHECKOUT_BOUND" "$REPLAY_CHECKOUT_PRESENT" "$REPLAY_GIT_BOUND" <<'PY'
import os
import stat
import subprocess
import sys

ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}
source, clean, replay, clean_root, replay_root, clean_bound, replay_root_bound, clean_child_bound, replay_child_bound, replay_child_present, replay_git_bound = sys.argv[1:]
repos = [('source', source)]
if clean_bound == '1':
    repos.append(('clean-primary', clean))
if replay_root_bound == '1' and replay_child_present == '1' and replay_git_bound == '1' and os.path.isdir(replay) and not os.path.islink(replay):
    repos.append(('replay', replay))
candidate_roots = [('clean-primary-root', clean_root), ('replay-root', replay_root)]
repo_by_owner = {'source': source, 'clean-primary': clean, 'replay': replay}

def root_state(path, label):
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} candidate is not canonical: {path}')
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return (path, 'absent')
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SystemExit(f'{label} candidate is not a real directory: {path}')
    return (path, 'present', str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o'))

def root_snapshot():
    return tuple((label, root_state(path, label)) for label, path in candidate_roots)

def overlap(a, b):
    if a == b:
        return True
    if not os.path.isabs(a) or not os.path.isabs(b):
        return False
    try:
        return os.path.commonpath([a, b]) in (a, b)
    except ValueError:
        return False

def identity(st):
    return (str(st.st_dev), str(st.st_ino), str(st.st_uid),
            format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink))

def occupied_forms(raw, repo, owner):
    if not isinstance(raw, str) or not raw or '\x00' in raw:
        raise SystemExit(f'{owner} registry block has a malformed empty worktree path')
    absolute = raw if os.path.isabs(raw) else os.path.abspath(os.path.join(repo, raw))
    forms = tuple(dict.fromkeys((raw, absolute, os.path.normpath(absolute), os.path.realpath(absolute))))
    try:
        st = os.lstat(absolute)
    except FileNotFoundError:
        return forms, ('missing',)
    except OSError as exc:
        raise SystemExit(f'{owner} registered worktree lstat failed: {raw}: {exc}')
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(absolute) != absolute:
        raise SystemExit(f'{owner} registered worktree is not a canonical real directory: {raw}')
    return forms, ('present', *identity(st))

def parse_records(output, owner, repo):
    rows, block = [], []
    def finish(lines):
        if not lines:
            return
        paths = [line[9:] for line in lines if line.startswith('worktree ')]
        if any(line == 'worktree' for line in lines) or len(paths) != 1 or not paths[0]:
            raise SystemExit(f'{owner} registry block is malformed or ambiguous')
        raw = paths[0]
        forms, state = occupied_forms(raw, repo, owner)
        rows.append((raw, forms, state, tuple(lines)))
    for line in output.splitlines():
        if line == '':
            finish(block); block = []
        else:
            block.append(line)
    finish(block)
    return tuple(rows)

def registry_snapshot():
    rows = []
    for owner, repo in repos:
        output = subprocess.check_output([
            '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks',
            '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-c', 'protocol.allow=never',
            'worktree', 'list', '--porcelain'], env=ENV, text=True)
        rows.append((owner, output, parse_records(output, owner, repo)))
    return tuple(rows)

def validate(rows, roots):
    targets = tuple(root[0] for _label, root in roots) + tuple(os.path.realpath(root[0]) for _label, root in roots)
    for owner, _output, records in rows:
        repo = repo_by_owner[owner]
        own, _own_state = occupied_forms(repo, repo, owner)
        own = set(own)
        for raw, forms, _state, _lines in records:
            if set(forms) & own:
                continue
            if any(overlap(item, target) for item in forms for target in targets):
                raise SystemExit(f'registered/nested worktree overlap: {raw}')

roots_before = root_snapshot()
registry_before = registry_snapshot()
validate(registry_before, roots_before)
if root_snapshot() != roots_before:
    raise SystemExit('root identity changed during worktree scan')
registry_after = registry_snapshot()
if registry_after != registry_before:
    raise SystemExit('registered worktree registry changed during scan')
if root_snapshot() != roots_before:
    raise SystemExit('root identity changed after worktree scan')
validate(registry_after, roots_before)
PY
}


assert_primary_pins() {
  assert_clean_primary_state
}


assert_status_paths() {
  "$PYTHON" - "$REPLAY" "$@" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import subprocess
import sys
repo = sys.argv[1]
expected = set(sys.argv[2:])
raw = subprocess.check_output([
    '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
    'status', '--porcelain=v1', '--untracked-files=all', '-z'
], env=ENV)
actual = set()
for record in raw.split(b'\0'):
    if not record:
        continue
    if len(record) < 4:
        raise SystemExit('malformed porcelain record')
    status = record[:2].decode(errors='strict')
    path = record[3:].decode(errors='strict')
    if status[0] in 'RC' or status[1] in 'RC':
        raise SystemExit(f'rename/copy status is not allowed: {path}')
    actual.add(path)
if actual != expected:
    raise SystemExit(f'status path mismatch: actual={sorted(actual)!r} expected={sorted(expected)!r}')
PY
}

assert_replay_object_binding() {
  "$PYTHON" - "$REPLAY" "$CLEAN_PRIMARY_OBJECTS" "$SOURCE_OBJECTS" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import os
import stat
import subprocess
import sys
repo, clean_objects, source_objects = sys.argv[1:]
git_dir = subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', 'rev-parse', '--absolute-git-dir'], text=True, env=ENV).strip()
objects = os.path.join(git_dir, 'objects')
repo_real = os.path.realpath(repo)
if repo_real != repo:
    raise SystemExit('replay repository path is not canonical')
required_files = (os.path.join(git_dir, 'HEAD'), os.path.join(git_dir, 'config'))
for required in required_files:
    required_st = os.lstat(required)
    if (stat.S_ISLNK(required_st.st_mode) or not stat.S_ISREG(required_st.st_mode)
            or required_st.st_nlink != 1 or os.path.realpath(required) != required):
        raise SystemExit('replay HEAD/config identity is not a regular canonical single-link file')
    read_stable_file(required, 'replay required metadata')
objects_st = os.lstat(objects)
if (stat.S_ISLNK(objects_st.st_mode) or not stat.S_ISDIR(objects_st.st_mode)
        or os.path.realpath(objects) != objects):
    raise SystemExit('replay object store is not a canonical directory')
info_dir = os.path.join(objects, 'info')
info_st = os.lstat(info_dir)
if (stat.S_ISLNK(info_st.st_mode) or not stat.S_ISDIR(info_st.st_mode)
        or os.path.realpath(info_dir) != info_dir):
    raise SystemExit('replay object info directory is not canonical')
dotgit = os.path.join(repo, '.git')
dotgit_st = os.lstat(dotgit)
if (stat.S_ISLNK(dotgit_st.st_mode) or not stat.S_ISDIR(dotgit_st.st_mode)
        or os.path.realpath(dotgit) != dotgit):
    raise SystemExit('replay Git directory is not a canonical directory')
if os.path.realpath(git_dir) != dotgit:
    raise SystemExit('replay Git directory is not the repository-local .git directory')
common_dir = subprocess.check_output([
    '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks',
    '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
    'rev-parse', '--git-common-dir',
], text=True, env=ENV).strip()
common_dir = os.path.realpath(common_dir if os.path.isabs(common_dir) else os.path.join(repo, common_dir))
if common_dir != git_dir:
    raise SystemExit('replay common directory is external or substituted')
if os.path.lexists(os.path.join(git_dir, 'commondir')):
    raise SystemExit('replay commondir indirection is forbidden')
for forbidden in (
    os.path.join(git_dir, 'shallow'),
    os.path.join(git_dir, 'info', 'grafts'),
    os.path.join(git_dir, 'refs', 'replace'),
    os.path.join(objects, 'info', 'http-alternates'),
):
    if os.path.lexists(forbidden):
        raise SystemExit('replay contains forbidden shallow, graft, replacement, or HTTP alternate metadata')
pack_dir = os.path.join(objects, 'pack')
if os.path.lexists(pack_dir) and (os.path.islink(pack_dir) or not os.path.isdir(pack_dir)
        or os.path.realpath(pack_dir) != pack_dir):
    raise SystemExit('replay pack directory is not canonical')
if os.path.isdir(pack_dir):
    for dirpath, dirnames, filenames in os.walk(pack_dir, topdown=True, followlinks=False):
        dirnames[:] = sorted(dirnames)
        filenames.sort()
        if any(os.path.islink(os.path.join(dirpath, name)) for name in dirnames):
            raise SystemExit('replay pack metadata contains a symlinked directory')
        if any(name.endswith('.promisor') for name in filenames):
            raise SystemExit('replay promisor metadata is forbidden')
alternate = os.path.join(objects, 'info', 'alternates')
st = os.lstat(alternate)
if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or os.path.realpath(alternate) != alternate:
    raise SystemExit('replay alternate is not a regular canonical file')
raw_alternate, _alternate_stat = read_stable_file(alternate, 'replay alternates')
if raw_alternate != (os.path.realpath(clean_objects) + '\n').encode():
    raise SystemExit('replay alternate is not clean-primary object store')
if os.path.samefile(objects, source_objects) or os.path.samefile(objects, clean_objects):
    raise SystemExit('replay object store is shared')
PY
}

assert_replay_state() {
  local expected_head="$1"
  local expected_tree="$2"
  shift 2
  test "$(git_replay rev-parse --show-toplevel)" = "$REPLAY" || fail "replay root changed"
  if git_replay symbolic-ref -q HEAD >/dev/null 2>&1; then fail "replay HEAD is attached"; fi
  test "$(git_replay rev-parse HEAD)" = "$expected_head" || fail "replay HEAD drifted"
  test "$(git_replay rev-parse HEAD^{tree})" = "$expected_tree" || fail "replay tree drifted"
  test "$(git_replay rev-parse refs/remotes/origin/dev)" = "$BASE" || fail "replay origin/dev drifted"
  test "$(git_replay rev-parse refs/remotes/origin/main)" = "$MAIN" || fail "replay origin/main drifted"
  assert_replay_object_binding
  assert_status_paths "$@"
}


assert_bootstrap_state() {
  test "$REPLAY_READY" -eq 0 || fail "bootstrap boundary used after replay became ready"
  test -z "$CURRENT_HEAD" || fail "bootstrap current HEAD is unexpectedly populated"
  test -z "$CURRENT_TREE" || fail "bootstrap current tree is unexpectedly populated"
  test "${#DIRTY_PATHS[@]}" -eq 0 || fail "bootstrap boundary has dirty transaction paths"
  # The descriptor-created replay child is intentionally not a Git repository
  # until init completes. Do not invoke Git or worktree-list before that point.
  if [ "$REPLAY_GIT_BOUND" -eq 0 ]; then
    return 0
  fi
  if git_replay rev-parse --verify refs/remotes/origin/dev >/dev/null 2>&1; then
    test "$(git_replay rev-parse refs/remotes/origin/dev)" = "$BASE" || fail "bootstrap replay origin/dev drifted"
  fi
  if git_replay rev-parse --verify refs/remotes/origin/main >/dev/null 2>&1; then
    test "$(git_replay rev-parse refs/remotes/origin/main)" = "$MAIN" || fail "bootstrap replay origin/main drifted"
  fi
  if [ -e "$REPLAY" ]; then
    if git_replay rev-parse --verify HEAD >/dev/null 2>&1; then
      test -n "$BOOTSTRAP_HEAD" || fail "bootstrap HEAD state is not declared"
      test -n "$BOOTSTRAP_TREE" || fail "bootstrap tree state is not declared"
      if git_replay symbolic-ref -q HEAD >/dev/null 2>&1; then
        fail "bootstrap replay HEAD is attached"
      fi
      test "$(git_replay rev-parse HEAD)" = "$BOOTSTRAP_HEAD" || fail "bootstrap HEAD drifted"
      test "$(git_replay rev-parse HEAD^{tree})" = "$BOOTSTRAP_TREE" || fail "bootstrap tree drifted"
      assert_status_paths
    else
      test -z "$BOOTSTRAP_HEAD" || fail "bootstrap HEAD declaration precedes HEAD creation"
      test -z "$BOOTSTRAP_TREE" || fail "bootstrap tree declaration precedes HEAD creation"
    fi
  else
    test -z "$BOOTSTRAP_HEAD" || fail "bootstrap HEAD declaration without replay checkout"
    test -z "$BOOTSTRAP_TREE" || fail "bootstrap tree declaration without replay checkout"
  fi
}

before_mutation() {
  assert_tools
  assert_root_shape
  assert_matrix_identity
  assert_source_binding
  assert_clean_primary_state
  assert_worktree_separation
  if [ "$REPLAY_READY" -eq 1 ]; then
    # Forward no optional arguments for an empty array. This is required for
    # Bash 3.2 nounset safety and keeps assert_replay_state's zero-arg contract.
    if [ "${#DIRTY_PATHS[@]}" -gt 0 ]; then
      assert_replay_state "$CURRENT_HEAD" "$CURRENT_TREE" "${DIRTY_PATHS[@]}"
    else
      assert_replay_state "$CURRENT_HEAD" "$CURRENT_TREE"
    fi
  else
    assert_bootstrap_state
  fi
}


add_dirty_path() {
  local candidate="$1"
  local existing
  # Do not expand an empty indexed array under Bash 3.2 nounset.
  if [ "${#DIRTY_PATHS[@]}" -gt 0 ]; then
    for existing in "${DIRTY_PATHS[@]}"; do
      [ "$existing" = "$candidate" ] && return 0
    done
  fi
  DIRTY_PATHS+=("$candidate")
}

assert_path_state() {
  "$PYTHON" - "$REPLAY" "$@" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat
import subprocess
import sys
repo, path, expected_blob, expected_mode, expected_kind = sys.argv[1:]
def run(*args, check=True):
    p = subprocess.run(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    if check and p.returncode:
        raise SystemExit(f'Git failed: {args!r}: {p.stderr.decode(errors="replace")}')
    return p
index = run('ls-files', '--stage', '--', path).stdout.decode()
full = os.path.join(repo, path)
if expected_kind == 'absent':
    if index or os.path.lexists(full):
        raise SystemExit(f'expected exact absence for {path}')
    raise SystemExit(0)
if expected_kind != 'file':
    raise SystemExit(f'unsupported expected kind {expected_kind!r}')
lines = index.rstrip('\n').splitlines()
if len(lines) != 1:
    raise SystemExit(f'index stage/absence mismatch for {path}')
mode, blob, rest = lines[0].split(' ', 2)
stage, recorded = rest.split('\t', 1)
if stage != '0' or recorded != path:
    raise SystemExit(f'index stage/path mismatch for {path}')
if mode != expected_mode or blob != expected_blob:
    raise SystemExit(f'index CAS mismatch for {path}: {(mode, blob)} != {(expected_mode, expected_blob)}')
if not os.path.isfile(full) or os.path.islink(full):
    raise SystemExit(f'worktree type mismatch for {path}')
actual_blob = run('hash-object', '--', path).stdout.decode().strip()
if actual_blob != expected_blob:
    raise SystemExit(f'worktree blob mismatch for {path}')
actual_mode = '100755' if stat.S_IXUSR & os.stat(full).st_mode else '100644'
if actual_mode != expected_mode:
    raise SystemExit(f'worktree mode mismatch for {path}')
if run('diff-files', '--quiet', '--', path, check=False).returncode != 0:
    raise SystemExit(f'worktree/index differ for {path}')
PY
}

assert_source_blob() {
  local source="$1"
  local path="$2"
  local expected="$3"
  local actual
  actual="$(git_replay rev-parse "$source:$path")"
  test "$actual" = "$expected" || fail "source target blob mismatch for $path"
  test "$(git_replay cat-file -t "$actual")" = blob || fail "source target is not a blob for $path"
}

assert_declared_projection() {
  local lane="$1"
  local selected="${2-}"
  local args=("$MATRIX" "$REPLAY" "$lane")
  [ -z "$selected" ] || args+=("$selected")
  "$PYTHON" - "${args[@]}" <<'PY'
import re

def strict_single_record_lf(raw, label='record'):
    """Parse one non-empty record with exactly one terminal LF."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must contain exactly one LF-framed record')
    record = raw[:-1]
    if not record or b'\n' in record:
        raise SystemExit(f'{label} must contain exactly one non-empty record')
    return record


def restore_command_substitution_lf(value, label='record'):
    """Put back the LF Bash command substitution removes before parsing."""
    if not isinstance(value, str) or not value or '\r' in value or '\n' in value:
        raise SystemExit(f'{label} command-substitution value is not one record')
    return strict_single_record_lf(value.encode('utf-8') + b'\n', label)


def strict_record_lines(raw, label='records'):
    """Parse a non-empty LF-framed stream without CR or blank rows."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must be LF-framed with no blank records')
    rows = raw[:-1].split(b'\n')
    if any(not row for row in rows):
        raise SystemExit(f'{label} contains an empty record')
    return rows


def strict_git_commit(value, label='Git commit'):
    """Require one complete lowercase SHA-1 commit token."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex')
    return value


def strict_git_parent_endpoint(value, label='Git parent endpoint'):
    """Require one complete lowercase SHA-1 token with one parent suffix."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}\^', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex^')
    return value


def strict_inclusive_git_range(record, label='Git range'):
    """Bind an inclusive notation to its separately validated endpoints."""
    if not isinstance(record, dict):
        raise SystemExit(f'{label} is not an object')
    left = strict_git_parent_endpoint(record.get('left'), f'{label}.left')
    right = strict_git_commit(record.get('right'), f'{label}.right')
    notation = record.get('notation')
    if (not isinstance(notation, str)
            or re.fullmatch(r'[0-9a-f]{40}\^\.\.[0-9a-f]{40}', notation) is None):
        raise SystemExit(f'{label}.notation is not lowercase 40hex^..40hex')
    if notation != f'{left}..{right}':
        raise SystemExit(f'{label}.notation does not match its validated endpoints')
    return left, right, notation


def strict_git_commit_range(value, label='Git commit range'):
    """Validate a two-commit range before either endpoint is used."""
    if (not isinstance(value, str)
            or re.fullmatch(r'[0-9a-f]{40}\.\.[0-9a-f]{40}', value) is None):
        raise SystemExit(f'{label} is not lowercase 40hex..40hex')
    left, right = value.split('..')
    return strict_git_commit(left, f'{label}.left'), strict_git_commit(right, f'{label}.right')

ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import os
import stat
import subprocess
import sys
import json
matrix, repo, lane_id = sys.argv[1:4]
selected = sys.argv[4] if len(sys.argv) == 5 else None
data = json.loads(read_stable_file(matrix, 'matrix')[0].decode('utf-8'))
lane = next(item for item in data['ordered_lanes'] if item['id'] == lane_id)

def run(*args, check=True):
    p = subprocess.run(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    if check and p.returncode:
        raise SystemExit(f'Git failed: {args!r}: {p.stderr.decode(errors="replace")}')
    return p

def tree_state(ref, path):
    raw = run('ls-tree', ref, '--', path).stdout.decode().splitlines()
    if not raw:
        return {'blob': None, 'mode': None, 'type': 'absent'}
    if len(raw) != 1:
        raise SystemExit(f'ambiguous declared tree state for {ref}:{path}')
    meta, recorded = raw[0].split('\t', 1)
    if recorded != path:
        raise SystemExit(f'declared tree path mismatch for {ref}:{path}')
    mode, kind, blob = meta.split()
    return {'blob': blob if kind == 'blob' else None, 'mode': mode, 'type': 'file' if kind == 'blob' else kind}

def content_state(path):
    full = os.path.join(repo, path)
    raw = run('ls-files', '--stage', '--', path).stdout.decode()
    if not raw:
        if os.path.lexists(full):
            return {'blob': None, 'mode': None, 'type': 'worktree-only'}
        return {'blob': None, 'mode': None, 'type': 'absent'}
    lines = raw.rstrip('\n').splitlines()
    if len(lines) != 1:
        raise SystemExit(f'index stage overlap for {path}')
    mode, blob, rest = lines[0].split(' ', 2)
    stage, recorded = rest.split('\t', 1)
    if stage != '0' or recorded != path:
        raise SystemExit(f'index stage/path mismatch for {path}')
    if not os.path.isfile(full) or os.path.islink(full):
        return {'blob': blob, 'mode': mode, 'type': 'worktree-nonfile'}
    actual_blob = run('hash-object', '--', path).stdout.decode().strip()
    actual_mode = '100755' if stat.S_IXUSR & os.stat(full).st_mode else '100644'
    if run('diff-files', '--quiet', '--', path, check=False).returncode != 0:
        return {'blob': actual_blob, 'mode': actual_mode, 'type': 'worktree-different'}
    return {'blob': actual_blob, 'mode': actual_mode, 'type': 'file'}

def compare(expected, actual, label):
    for key in ('blob', 'mode', 'type'):
        if actual.get(key) != expected.get(key):
            raise SystemExit(f'{label}: {key} mismatch: actual={actual.get(key)!r} expected={expected.get(key)!r}')

def validate_tree_record(record, path, label):
    tree_commit = record.get('tree_commit')
    if not isinstance(tree_commit, str) or len(tree_commit) != 40:
        raise SystemExit(f'{label}.{path}: missing full tree commit')
    expected_tree = record.get('tree')
    actual_tree = run('rev-parse', f'{tree_commit}^{{tree}}').stdout.decode().strip()
    if actual_tree != expected_tree:
        raise SystemExit(f'{label}.{path}: tree mismatch')
    compare(record, tree_state(tree_commit, path), f'{label}.{path}.tree')

source = lane.get('source_parent_state')
stage = lane.get('stage_precondition')
if not source or not stage:
    raise SystemExit(f'{lane_id}: declared source-parent/stage state maps are required')
source_commit = source.get('commit')
source_tree = source.get('tree')
if run('rev-parse', f'{source_commit}^{{tree}}').stdout.decode().strip() != source_tree:
    raise SystemExit(f'{lane_id}: source-parent tree binding mismatch')
for path, record in source['paths'].items():
    record = dict(record)
    record['tree_commit'] = source_commit
    validate_tree_record(record, path, f'{lane_id}.source-parent')

stage_paths = stage['paths']
selected_paths = [selected] if selected is not None else list(stage_paths)
for path in selected_paths:
    if path not in stage_paths:
        raise SystemExit(f'{lane_id}: undeclared stage path {path}')
    record = stage_paths[path]
    validate_tree_record(record, path, f'{lane_id}.stage')
    compare(record, content_state(path), f'{lane_id}.stage.current')
PY
}

cas_path() {
  # This is a compare-and-swap transaction: old index blob/mode/stage, old worktree
  # blob/mode/type or absence are checked before update-index; target is checked after
  # both index and worktree updates. No path-wide source apply is used.
  local path="$1" old_blob="$2" old_mode="$3" old_kind="$4"
  local new_blob="$5" new_mode="$6" new_kind="$7"
  assert_path_state "$path" "$old_blob" "$old_mode" "$old_kind"
  # Callers add no optimistic dirty entry for this path. The entry is added only
  # after update-index succeeds, so the pre-CAS boundary cannot accept a clean path
  # that has merely been listed as dirty in advance.
  if [ "$new_kind" = absent ]; then
    before_mutation
    git_replay update-index --force-remove -- "$path" 2>/dev/null || true
    add_dirty_path "$path"
    before_mutation
    if [ -e "$REPLAY/$path" ] || [ -L "$REPLAY/$path" ]; then
      "$RM" -f -- "$REPLAY/$path"
    fi
  else
    test "$new_kind" = file || fail "unsupported target type for $path"
    test "$new_mode" = 100644 || test "$new_mode" = 100755 || fail "unsupported target mode for $path"
    test "$(git_replay cat-file -t "$new_blob")" = blob || fail "target blob is not local for $path"
    before_mutation
    git_replay update-index --add --cacheinfo "$new_mode,$new_blob,$path"
    add_dirty_path "$path"
    before_mutation
    git_replay checkout-index --force -- "$path"
  fi
  assert_path_state "$path" "$new_blob" "$new_mode" "$new_kind"
}

assert_exact_staged() {
  "$PYTHON" - "$REPLAY" "$@" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import subprocess
import sys
repo = sys.argv[1]
expected = set(sys.argv[2:])
raw = subprocess.check_output([
    '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
    'diff', '--cached', '--name-only', '-z', '--'
], env=ENV)
actual = set(x.decode() for x in raw.split(b'\0') if x)
if not actual:
    raise SystemExit('staged result is empty')
if actual != expected:
    raise SystemExit(f'staged path mismatch: actual={sorted(actual)!r} expected={sorted(expected)!r}')
PY
}

binary_patch_id() {
  local left="$1" right="$2"
  shift 2
  git_replay diff --binary --full-index --no-ext-diff --no-textconv "$left" "$right" -- "$@" \
    | patch_id_stable | "$CUT" -d' ' -f1
}
raw_patch_sha256() {
  local left="$1" right="$2"
  shift 2
  git_replay diff --binary --full-index --no-ext-diff --no-textconv "$left" "$right" -- "$@" \
    | "$SHASUM" -a 256 | "$CUT" -d' ' -f1
}

assert_cached_patch() {
  local expected="$1"
  shift
  local raw patch
  raw="$(git_replay diff --cached --binary --full-index --no-ext-diff --no-textconv -- "$@")"
  test -n "$raw" || fail "empty staged binary patch"
  patch="$(printf '%s' "$raw" | patch_id_stable | "$CUT" -d' ' -f1)"
  if [ "$expected" != - ]; then
    test "$patch" = "$expected" || fail "staged patch-id mismatch: $patch != $expected"
  fi
}

assert_commit_target_states() {
  local head="$1"
  shift
  "$PYTHON" - "$REPLAY" "$head" "$@" <<'PY'
import os
import subprocess
import sys

repo, head = sys.argv[1:3]
arguments = sys.argv[3:]
try:
    separator = arguments.index('--')
except ValueError:
    raise SystemExit('commit target verifier is missing its path/row separator')
paths = arguments[:separator]
rows = arguments[separator + 1:]
if len(paths) != len(rows) or len(set(paths)) != len(paths):
    raise SystemExit('commit target verifier path/row cardinality mismatch')
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}
def run(*args):
    command = [
        '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks',
        '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
        *args,
    ]
    process = subprocess.run(command, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode:
        raise SystemExit(f'Git target-state check failed: {args!r}: {process.stderr.decode(errors="replace")}')
    return process.stdout
for row in rows:
    fields = row.split('\t')
    if len(fields) != 4:
        raise SystemExit(f'malformed expected target row: {row!r}')
    path, expected_blob, expected_mode, expected_kind = fields
    raw = run('ls-tree', head, '--', path).decode()
    if expected_kind == 'absent':
        if raw:
            raise SystemExit(f'expected absent path is present in HEAD: {path}')
        continue
    if expected_kind != 'file' or expected_blob == '-' or expected_mode == '-':
        raise SystemExit(f'invalid expected target state: {row!r}')
    lines = raw.splitlines()
    if len(lines) != 1:
        raise SystemExit(f'HEAD target path is missing or ambiguous: {path}')
    meta, recorded = lines[0].split('\t', 1)
    mode, kind, oid = meta.split()
    if recorded != path:
        raise SystemExit(f'HEAD target path mismatch: {path}')
    if kind != 'blob' or oid != expected_blob or mode != expected_mode:
        raise SystemExit(f'HEAD target state mismatch for {path}: {(oid, mode, kind)} != {(expected_blob, expected_mode, "blob")}')
    actual_type = run('cat-file', '-t', oid).decode().strip()
    if actual_type != 'blob':
        raise SystemExit(f'HEAD target object type mismatch for {path}: {actual_type} != blob')
PY
}

assert_commit_gate() {
  local parent="$1" head="$2" expected_patch="$3"
  shift 3
  local paths=("$@") raw patch
  test "${#EXPECTED_COMMIT_TARGET_ROWS[@]}" -eq "${#paths[@]}" || fail "declared commit target row count mismatch"
  assert_commit_target_states "$head" "${paths[@]}" -- "${EXPECTED_COMMIT_TARGET_ROWS[@]}"
  test "$(git_replay rev-parse "$head^")" = "$parent" || fail "post-commit parent mismatch"
  assert_exact_commit_paths "$head" "${paths[@]}"
  raw="$(git_replay diff --binary --full-index --no-ext-diff --no-textconv "$parent" "$head" -- "${paths[@]}")"
  test -n "$raw" || fail "post-commit binary patch is empty"
  git_replay diff --check "$parent" "$head" -- "${paths[@]}"
  if [ "$expected_patch" != - ]; then
    patch="$(printf '%s' "$raw" | patch_id_stable | "$CUT" -d' ' -f1)"
    test "$patch" = "$expected_patch" || fail "post-commit patch-id mismatch: $patch != $expected_patch"
  fi
}

assert_exact_commit_paths() {
  local head="$1"
  shift
  "$PYTHON" - "$REPLAY" "$head" "$@" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import subprocess
import sys
repo, head = sys.argv[1:3]
expected = set(sys.argv[3:])
raw = subprocess.check_output([
    '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
    'diff-tree', '--root', '--no-commit-id', '--name-only', '-r', '-z', head
], env=ENV)
actual = set(x.decode() for x in raw.split(b'\0') if x)
if actual != expected:
    raise SystemExit(f'commit path mismatch: actual={sorted(actual)!r} expected={sorted(expected)!r}')
PY
}

assert_unique_patch_id() {
  local value="$1"
  [ "$value" = - ] && return 0
  case "|$APPLIED_PATCH_IDS|" in
    *"|$value|"*) fail "stable patch-id would be applied twice: $value" ;;
  esac
  APPLIED_PATCH_IDS="${APPLIED_PATCH_IDS}${value}|"
}

target_state_record() {
  local path="$1"
  "$PYTHON" - "$MATRIX" "$path" <<'PY'
import re

def strict_single_record_lf(raw, label='record'):
    """Parse one non-empty record with exactly one terminal LF."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must contain exactly one LF-framed record')
    record = raw[:-1]
    if not record or b'\n' in record:
        raise SystemExit(f'{label} must contain exactly one non-empty record')
    return record


def restore_command_substitution_lf(value, label='record'):
    """Put back the LF Bash command substitution removes before parsing."""
    if not isinstance(value, str) or not value or '\r' in value or '\n' in value:
        raise SystemExit(f'{label} command-substitution value is not one record')
    return strict_single_record_lf(value.encode('utf-8') + b'\n', label)


def strict_record_lines(raw, label='records'):
    """Parse a non-empty LF-framed stream without CR or blank rows."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must be LF-framed with no blank records')
    rows = raw[:-1].split(b'\n')
    if any(not row for row in rows):
        raise SystemExit(f'{label} contains an empty record')
    return rows


def strict_git_commit(value, label='Git commit'):
    """Require one complete lowercase SHA-1 commit token."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex')
    return value


def strict_git_parent_endpoint(value, label='Git parent endpoint'):
    """Require one complete lowercase SHA-1 token with one parent suffix."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}\^', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex^')
    return value


def strict_inclusive_git_range(record, label='Git range'):
    """Bind an inclusive notation to its separately validated endpoints."""
    if not isinstance(record, dict):
        raise SystemExit(f'{label} is not an object')
    left = strict_git_parent_endpoint(record.get('left'), f'{label}.left')
    right = strict_git_commit(record.get('right'), f'{label}.right')
    notation = record.get('notation')
    if (not isinstance(notation, str)
            or re.fullmatch(r'[0-9a-f]{40}\^\.\.[0-9a-f]{40}', notation) is None):
        raise SystemExit(f'{label}.notation is not lowercase 40hex^..40hex')
    if notation != f'{left}..{right}':
        raise SystemExit(f'{label}.notation does not match its validated endpoints')
    return left, right, notation


def strict_git_commit_range(value, label='Git commit range'):
    """Validate a two-commit range before either endpoint is used."""
    if (not isinstance(value, str)
            or re.fullmatch(r'[0-9a-f]{40}\.\.[0-9a-f]{40}', value) is None):
        raise SystemExit(f'{label} is not lowercase 40hex..40hex')
    left, right = value.split('..')
    return strict_git_commit(left, f'{label}.left'), strict_git_commit(right, f'{label}.right')

import json
import os
import stat
import sys


def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

matrix, path = sys.argv[1:]
data = json.loads(read_stable_file(matrix, 'matrix source')[0].decode('utf-8'))
found = []
for lane in data['ordered_lanes']:
    for sequence in (lane.get('range', {}).get('source_commits', []), [lane.get('source_commit')] if lane.get('source_commit') else []):
        for commit in sequence:
            if commit and path in commit.get('target_states', {}):
                state = commit['target_states'][path]
                found.append((lane['id'], 'commit', commit['commit'], state))
    for map_name, state_map in (('stage', lane.get('stage_precondition', {}).get('paths', {})), ('parent', lane.get('source_parent_state', {}).get('paths', {}))):
        if path in state_map:
            found.append((lane['id'], map_name, lane.get('order'), state_map[path]))
if not found:
    raise SystemExit(f'no declared target state for committed path: {path}')
# A path may be repeated by later lanes, but a commit must match one exact declared
# state. Reject ambiguity instead of silently selecting the first lane's state.
unique = {(item[3].get('blob'), item[3].get('mode'), item[3].get('type')) for item in found}
if len(unique) != 1:
    raise SystemExit(f'ambiguous declared target state for committed path: {path}')
state = found[-1][3]
print('\t'.join([path, state.get('blob') or '-', state.get('mode') or '-', state.get('type') or 'absent']))
PY
}

commit_staged() {
  local message="$1" expected_patch="$2"
  shift 2
  local paths=("$@") parent staged_raw staged_patch expected_tree
  local EXPECTED_COMMIT_TARGET_ROWS=() target_path target_state
  for target_path in "${paths[@]}"; do
    target_state="$(target_state_record "$target_path")"
    EXPECTED_COMMIT_TARGET_ROWS+=("$target_state")
  done
  assert_exact_staged "${paths[@]}"
  git_replay diff --cached --check -- "${paths[@]}"
  expected_tree="$(git_replay write-tree)" || fail "staged index tree could not be pinned"
  test -n "$expected_tree" || fail "staged index tree is empty"
  staged_raw="$(git_replay diff --cached --binary --full-index --no-ext-diff --no-textconv -- "${paths[@]}")"
  test -n "$staged_raw" || fail "empty staged binary patch"
  staged_patch="$(printf '%s' "$staged_raw" | patch_id_stable | "$CUT" -d' ' -f1)"
  test -n "$staged_patch" || fail "empty staged patch-id"
  if [ "$expected_patch" = - ]; then
    assert_unique_patch_id "$staged_patch"
  else
    assert_unique_patch_id "$expected_patch"
  fi
  parent="$CURRENT_HEAD"
  before_mutation
  git_replay -c user.name="$COMMITTER_NAME" -c user.email="$COMMITTER_EMAIL" commit --no-verify -m "$message"
  CURRENT_HEAD="$(git_replay rev-parse HEAD)"
  CURRENT_TREE="$(git_replay rev-parse HEAD^{tree})"
  test "$CURRENT_TREE" = "$expected_tree" || fail "post-commit tree differs from pinned staged tree"
  DIRTY_PATHS=()
  assert_replay_state "$CURRENT_HEAD" "$CURRENT_TREE"
  assert_commit_gate "$parent" "$CURRENT_HEAD" "$expected_patch" "${paths[@]}"
}

range_records() {
  local lane="$1"
  "$PYTHON" - "$MATRIX" "$lane" <<'PY'
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import json
import sys
m = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8'))
lane = next(x for x in m['ordered_lanes'] if x['id'] == sys.argv[2])
for c in lane['range']['source_commits']:
    print('\t'.join([
        c['commit'], c['stable_patch_id'], c['parents'][0], c['tree'],
        '\x1f'.join(c['changed_paths'])
    ]))
PY
}

range_target_records() {
  local lane="$1"
  local source="$2"
  "$PYTHON" - "$MATRIX" "$lane" "$source" <<'PY'
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import json
import sys
m = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8'))
lane = next(x for x in m['ordered_lanes'] if x['id'] == sys.argv[2])
source = sys.argv[3]
commit = next(c for c in lane['range']['source_commits'] if c['commit'] == source)
for path in commit['changed_paths']:
    state = commit['target_states'][path]
    print('\t'.join([path, state['blob'] or '-', state['mode'] or '-', state['type']]))
PY
}

assert_range_records_file() {
  local lane="$1" file="$2"
  "$PYTHON" - "$MATRIX" "$lane" "$file" <<'PY'
import re

def strict_single_record_lf(raw, label='record'):
    """Parse one non-empty record with exactly one terminal LF."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must contain exactly one LF-framed record')
    record = raw[:-1]
    if not record or b'\n' in record:
        raise SystemExit(f'{label} must contain exactly one non-empty record')
    return record


def restore_command_substitution_lf(value, label='record'):
    """Put back the LF Bash command substitution removes before parsing."""
    if not isinstance(value, str) or not value or '\r' in value or '\n' in value:
        raise SystemExit(f'{label} command-substitution value is not one record')
    return strict_single_record_lf(value.encode('utf-8') + b'\n', label)


def strict_record_lines(raw, label='records'):
    """Parse a non-empty LF-framed stream without CR or blank rows."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must be LF-framed with no blank records')
    rows = raw[:-1].split(b'\n')
    if any(not row for row in rows):
        raise SystemExit(f'{label} contains an empty record')
    return rows


def strict_git_commit(value, label='Git commit'):
    """Require one complete lowercase SHA-1 commit token."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex')
    return value


def strict_git_parent_endpoint(value, label='Git parent endpoint'):
    """Require one complete lowercase SHA-1 token with one parent suffix."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}\^', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex^')
    return value


def strict_inclusive_git_range(record, label='Git range'):
    """Bind an inclusive notation to its separately validated endpoints."""
    if not isinstance(record, dict):
        raise SystemExit(f'{label} is not an object')
    left = strict_git_parent_endpoint(record.get('left'), f'{label}.left')
    right = strict_git_commit(record.get('right'), f'{label}.right')
    notation = record.get('notation')
    if (not isinstance(notation, str)
            or re.fullmatch(r'[0-9a-f]{40}\^\.\.[0-9a-f]{40}', notation) is None):
        raise SystemExit(f'{label}.notation is not lowercase 40hex^..40hex')
    if notation != f'{left}..{right}':
        raise SystemExit(f'{label}.notation does not match its validated endpoints')
    return left, right, notation


def strict_git_commit_range(value, label='Git commit range'):
    """Validate a two-commit range before either endpoint is used."""
    if (not isinstance(value, str)
            or re.fullmatch(r'[0-9a-f]{40}\.\.[0-9a-f]{40}', value) is None):
        raise SystemExit(f'{label} is not lowercase 40hex..40hex')
    left, right = value.split('..')
    return strict_git_commit(left, f'{label}.left'), strict_git_commit(right, f'{label}.right')

import json
import sys
from pathlib import Path
matrix, lane_id, output = sys.argv[1:]
data = json.loads(Path(matrix).read_bytes())
lane = next(row for row in data['ordered_lanes'] if row['id'] == lane_id)
sequence = lane['range']
expected = []
for commit in sequence['source_commits']:
    expected.append('\t'.join([commit['commit'], commit['stable_patch_id'], commit['parents'][0], commit['tree'], '\x1f'.join(commit['changed_paths'])]).encode())
raw = Path(output).read_bytes()
actual = strict_record_lines(raw, f'{lane_id}: range records')
if len(actual) != sequence['count'] or actual != expected:
    raise SystemExit(f'{lane_id}: range records are empty, truncated, reordered, or have tail loss')
PY
}
assert_range_target_records_file() {
  local lane="$1" source="$2" file="$3"
  "$PYTHON" - "$MATRIX" "$lane" "$source" "$file" <<'PY'
import re

def strict_single_record_lf(raw, label='record'):
    """Parse one non-empty record with exactly one terminal LF."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must contain exactly one LF-framed record')
    record = raw[:-1]
    if not record or b'\n' in record:
        raise SystemExit(f'{label} must contain exactly one non-empty record')
    return record


def restore_command_substitution_lf(value, label='record'):
    """Put back the LF Bash command substitution removes before parsing."""
    if not isinstance(value, str) or not value or '\r' in value or '\n' in value:
        raise SystemExit(f'{label} command-substitution value is not one record')
    return strict_single_record_lf(value.encode('utf-8') + b'\n', label)


def strict_record_lines(raw, label='records'):
    """Parse a non-empty LF-framed stream without CR or blank rows."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must be LF-framed with no blank records')
    rows = raw[:-1].split(b'\n')
    if any(not row for row in rows):
        raise SystemExit(f'{label} contains an empty record')
    return rows


def strict_git_commit(value, label='Git commit'):
    """Require one complete lowercase SHA-1 commit token."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex')
    return value


def strict_git_parent_endpoint(value, label='Git parent endpoint'):
    """Require one complete lowercase SHA-1 token with one parent suffix."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}\^', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex^')
    return value


def strict_inclusive_git_range(record, label='Git range'):
    """Bind an inclusive notation to its separately validated endpoints."""
    if not isinstance(record, dict):
        raise SystemExit(f'{label} is not an object')
    left = strict_git_parent_endpoint(record.get('left'), f'{label}.left')
    right = strict_git_commit(record.get('right'), f'{label}.right')
    notation = record.get('notation')
    if (not isinstance(notation, str)
            or re.fullmatch(r'[0-9a-f]{40}\^\.\.[0-9a-f]{40}', notation) is None):
        raise SystemExit(f'{label}.notation is not lowercase 40hex^..40hex')
    if notation != f'{left}..{right}':
        raise SystemExit(f'{label}.notation does not match its validated endpoints')
    return left, right, notation


def strict_git_commit_range(value, label='Git commit range'):
    """Validate a two-commit range before either endpoint is used."""
    if (not isinstance(value, str)
            or re.fullmatch(r'[0-9a-f]{40}\.\.[0-9a-f]{40}', value) is None):
        raise SystemExit(f'{label} is not lowercase 40hex..40hex')
    left, right = value.split('..')
    return strict_git_commit(left, f'{label}.left'), strict_git_commit(right, f'{label}.right')

import json
import sys
from pathlib import Path
matrix, lane_id, source, output = sys.argv[1:]
data = json.loads(Path(matrix).read_bytes())
lane = next(row for row in data['ordered_lanes'] if row['id'] == lane_id)
commit = next(row for row in lane['range']['source_commits'] if row['commit'] == source)
expected = []
for path in commit['changed_paths']:
    state = commit['target_states'][path]
    expected.append('\t'.join([path, state['blob'] or '-', state['mode'] or '-', state['type']]).encode())
raw = Path(output).read_bytes()
actual = strict_record_lines(raw, 'validated records')
if not expected or actual != expected:
    raise SystemExit(f'{lane_id}:{source}: target records are empty, truncated, reordered, or have tail loss')
PY
}
assert_semantic_records_file() {
  local lane="$1" file="$2"
  "$PYTHON" - "$MATRIX" "$lane" "$file" <<'PY'
import re

def strict_single_record_lf(raw, label='record'):
    """Parse one non-empty record with exactly one terminal LF."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must contain exactly one LF-framed record')
    record = raw[:-1]
    if not record or b'\n' in record:
        raise SystemExit(f'{label} must contain exactly one non-empty record')
    return record


def restore_command_substitution_lf(value, label='record'):
    """Put back the LF Bash command substitution removes before parsing."""
    if not isinstance(value, str) or not value or '\r' in value or '\n' in value:
        raise SystemExit(f'{label} command-substitution value is not one record')
    return strict_single_record_lf(value.encode('utf-8') + b'\n', label)


def strict_record_lines(raw, label='records'):
    """Parse a non-empty LF-framed stream without CR or blank rows."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must be LF-framed with no blank records')
    rows = raw[:-1].split(b'\n')
    if any(not row for row in rows):
        raise SystemExit(f'{label} contains an empty record')
    return rows


def strict_git_commit(value, label='Git commit'):
    """Require one complete lowercase SHA-1 commit token."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex')
    return value


def strict_git_parent_endpoint(value, label='Git parent endpoint'):
    """Require one complete lowercase SHA-1 token with one parent suffix."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}\^', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex^')
    return value


def strict_inclusive_git_range(record, label='Git range'):
    """Bind an inclusive notation to its separately validated endpoints."""
    if not isinstance(record, dict):
        raise SystemExit(f'{label} is not an object')
    left = strict_git_parent_endpoint(record.get('left'), f'{label}.left')
    right = strict_git_commit(record.get('right'), f'{label}.right')
    notation = record.get('notation')
    if (not isinstance(notation, str)
            or re.fullmatch(r'[0-9a-f]{40}\^\.\.[0-9a-f]{40}', notation) is None):
        raise SystemExit(f'{label}.notation is not lowercase 40hex^..40hex')
    if notation != f'{left}..{right}':
        raise SystemExit(f'{label}.notation does not match its validated endpoints')
    return left, right, notation


def strict_git_commit_range(value, label='Git commit range'):
    """Validate a two-commit range before either endpoint is used."""
    if (not isinstance(value, str)
            or re.fullmatch(r'[0-9a-f]{40}\.\.[0-9a-f]{40}', value) is None):
        raise SystemExit(f'{label} is not lowercase 40hex..40hex')
    left, right = value.split('..')
    return strict_git_commit(left, f'{label}.left'), strict_git_commit(right, f'{label}.right')

import json
import sys
from pathlib import Path
matrix, lane_id, output = sys.argv[1:]
data = json.loads(Path(matrix).read_bytes())
lane = next(row for row in data['ordered_lanes'] if row['id'] == lane_id)
if lane_id == 'dependency-audit-correction':
    target = lane['source_commit']['commit']; parent = lane['source_commit']['parents'][0]; paths = lane['owned_paths']
else:
    target = lane['semantic_delta']['child']; parent = lane['semantic_delta']['parent']; paths = lane['semantic_delta']['owned_paths']
expected = [target.encode(), parent.encode(), '\x1f'.join(paths).encode()]
raw = Path(output).read_bytes()
actual = strict_record_lines(raw, 'validated records')
if actual != expected:
    raise SystemExit(f'{lane_id}: semantic records are empty, truncated, reordered, or have tail loss')
PY
}
assert_projection_stage_records_file() {
  local lane="$1" file="$2"
  "$PYTHON" - "$MATRIX" "$lane" "$file" <<'PY'
import re

def strict_single_record_lf(raw, label='record'):
    """Parse one non-empty record with exactly one terminal LF."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must contain exactly one LF-framed record')
    record = raw[:-1]
    if not record or b'\n' in record:
        raise SystemExit(f'{label} must contain exactly one non-empty record')
    return record


def restore_command_substitution_lf(value, label='record'):
    """Put back the LF Bash command substitution removes before parsing."""
    if not isinstance(value, str) or not value or '\r' in value or '\n' in value:
        raise SystemExit(f'{label} command-substitution value is not one record')
    return strict_single_record_lf(value.encode('utf-8') + b'\n', label)


def strict_record_lines(raw, label='records'):
    """Parse a non-empty LF-framed stream without CR or blank rows."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must be LF-framed with no blank records')
    rows = raw[:-1].split(b'\n')
    if any(not row for row in rows):
        raise SystemExit(f'{label} contains an empty record')
    return rows


def strict_git_commit(value, label='Git commit'):
    """Require one complete lowercase SHA-1 commit token."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex')
    return value


def strict_git_parent_endpoint(value, label='Git parent endpoint'):
    """Require one complete lowercase SHA-1 token with one parent suffix."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}\^', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex^')
    return value


def strict_inclusive_git_range(record, label='Git range'):
    """Bind an inclusive notation to its separately validated endpoints."""
    if not isinstance(record, dict):
        raise SystemExit(f'{label} is not an object')
    left = strict_git_parent_endpoint(record.get('left'), f'{label}.left')
    right = strict_git_commit(record.get('right'), f'{label}.right')
    notation = record.get('notation')
    if (not isinstance(notation, str)
            or re.fullmatch(r'[0-9a-f]{40}\^\.\.[0-9a-f]{40}', notation) is None):
        raise SystemExit(f'{label}.notation is not lowercase 40hex^..40hex')
    if notation != f'{left}..{right}':
        raise SystemExit(f'{label}.notation does not match its validated endpoints')
    return left, right, notation


def strict_git_commit_range(value, label='Git commit range'):
    """Validate a two-commit range before either endpoint is used."""
    if (not isinstance(value, str)
            or re.fullmatch(r'[0-9a-f]{40}\.\.[0-9a-f]{40}', value) is None):
        raise SystemExit(f'{label} is not lowercase 40hex..40hex')
    left, right = value.split('..')
    return strict_git_commit(left, f'{label}.left'), strict_git_commit(right, f'{label}.right')

import json
import sys
from pathlib import Path
matrix, lane_id, output = sys.argv[1:]
data = json.loads(Path(matrix).read_bytes())
lane = next(row for row in data['ordered_lanes'] if row['id'] == lane_id)
paths = lane.get('semantic_delta', {}).get('owned_paths') or lane['owned_paths']
expected = []
for path in paths:
    state = lane['stage_precondition']['paths'][path]
    expected.append('\t'.join([path, state['blob'] or '-', state['mode'] or '-', state['type']]).encode())
raw = Path(output).read_bytes()
actual = strict_record_lines(raw, 'validated records')
if not expected or actual != expected:
    raise SystemExit(f'{lane_id}: projection records are empty, truncated, reordered, or have tail loss')
PY
}
assert_matrix_records_file() {
  local stage="$1" file="$2"
  "$PYTHON" - "$MATRIX" "$stage" "$file" <<'PY'
import json
import sys
from pathlib import Path
matrix, stage, output = sys.argv[1:]
data = json.loads(Path(matrix).read_bytes())
expected = []
for row in data['live_overlap']['blob_matrix']:
    if stage == 'launcher' and row['launcher_mechanical']:
        expected.append('\t'.join([row['path'], row['proxy_blob'] or '-', row['proxy_mode'] or '-', row['d3_launcher_blob'] or '-', row['d3_launcher_mode'] or '-']).encode())
    if stage == 'live' and row['live_mechanical']:
        old_blob = row['d3_launcher_blob'] if row['launcher_mechanical'] else row['proxy_blob']
        old_mode = row['d3_launcher_mode'] if row['launcher_mechanical'] else row['proxy_mode']
        expected.append('\t'.join([row['path'], old_blob or '-', old_mode or '-', row['80fe_live_blob'] or '-', row['80fe_live_mode'] or '-']).encode())
raw = Path(output).read_bytes()
actual = strict_record_lines(raw, 'validated records')
if not expected or actual != expected:
    raise SystemExit(f'{stage}: matrix records are empty, truncated, reordered, or have tail loss')
PY
}
forbidden_ancestry_records() {
  "$PYTHON" - "$MATRIX" <<'PY'
import json
import sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_bytes())
for value in data['forbidden_ancestry']['commits'] + data['forbidden_ancestry']['raw_semantic_source_commits']:
    print(value)
PY
}
assert_forbidden_ancestry_records_file() {
  local file="$1"
  "$PYTHON" - "$MATRIX" "$file" <<'PY'
import json
import sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_bytes())
expected = [value.encode() for value in data['forbidden_ancestry']['commits'] + data['forbidden_ancestry']['raw_semantic_source_commits']]
raw = Path(sys.argv[2]).read_bytes()
actual = strict_record_lines(raw, 'forbidden ancestry records')
if not expected or actual != expected:
    raise SystemExit('forbidden ancestry records are empty, truncated, reordered, or have tail loss')
PY
}

apply_range_lane() {
  local lane="$1" record source expected parent tree path_blob cherry_path abort_rc
  local paths=()
  local records_file target_records_file
  records_file="$(producer_to_file range-records "$REPLAY_ROOT" range_records "$lane")"
  assert_range_records_file "$lane" "$records_file"
  while IFS=$'	' read -r source expected parent tree path_blob; do
    [ -n "$source" ] || continue
    test "$(git_replay rev-parse "$source^")" = "$parent" || fail "source parent mismatch for $source"
    test "$(git_replay rev-parse "$source^{tree}")" = "$tree" || fail "source tree mismatch for $source"
    IFS=$'' read -r -a paths <<< "$path_blob"
    test "${#paths[@]}" -gt 0 || fail "empty source path set for $source"
    cherry_path="$(git_replay cherry "$CURRENT_HEAD" "$source")"
    test -n "$cherry_path" || fail "git cherry returned an empty duplicate-check result for $source"
    while IFS= read -r record; do
      case "$record" in -*) fail "duplicate source patch rejected by git cherry: $record" ;; esac
    done <<< "$cherry_path"
    DIRTY_PATHS=()
    before_mutation
    if git_replay cherry-pick --no-commit "$source"; then
      :
    else
      DIRTY_PATHS=("${paths[@]}")
      before_mutation
      if git_replay cherry-pick --abort; then
        :
      else
        abort_rc=$?
        fail "cherry-pick abort failed in $lane at $source with rc=$abort_rc"
      fi
      DIRTY_PATHS=()
      before_mutation
      fail "cherry-pick conflict in $lane at $source"
    fi
    DIRTY_PATHS=("${paths[@]}")
    assert_replay_state "$CURRENT_HEAD" "$CURRENT_TREE" "${DIRTY_PATHS[@]}"
    target_records_file="$(producer_to_file range-target-records "$REPLAY_ROOT" range_target_records "$lane" "$source")"
    assert_range_target_records_file "$lane" "$source" "$target_records_file"
    while IFS=$'	' read -r path target_blob target_mode target_kind; do
      assert_path_state "$path" "$target_blob" "$target_mode" "$target_kind"
    done < "$target_records_file"
    cleanup_temp_file "$target_records_file"
    assert_exact_staged "${paths[@]}"
    git_replay diff --cached --check -- "${paths[@]}"
    test "$(binary_patch_id "$parent" "$source" "${paths[@]}")" = "$expected" || fail "source patch-id mismatch for $source"
    assert_cached_patch "$expected" "${paths[@]}"
    commit_staged "replay(task409): $lane:$source" "$expected" "${paths[@]}"
  done < "$records_file"
  cleanup_temp_file "$records_file"
}


semantic_records() {
  local lane="$1"
  "$PYTHON" - "$MATRIX" "$lane" <<'PY'
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import json
import sys
m = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8'))
lane = next(x for x in m['ordered_lanes'] if x['id'] == sys.argv[2])
if lane['id'] == 'dependency-audit-correction':
    target = lane['source_commit']['commit']
    parent = lane['source_commit']['parents'][0]
    paths = lane['owned_paths']
else:
    target = lane['semantic_delta']['child']
    parent = lane['semantic_delta']['parent']
    paths = lane['semantic_delta']['owned_paths']
print(target)
print(parent)
print('\x1f'.join(paths))
PY
}


snapshot_paths() {
  "$PYTHON" - "$REPLAY" "$@" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat
import subprocess
import sys
repo = sys.argv[1]
for path in sys.argv[2:]:
    p = subprocess.run(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', 'ls-files', '--stage', '--', path], stdout=subprocess.PIPE, check=True, env=ENV)
    raw = p.stdout.decode()
    if not raw:
        if os.path.lexists(os.path.join(repo, path)):
            raise SystemExit(f'non-indexed worktree path is not exact absence: {path}')
        print(f'{path}\t-\t-\tabsent')
        continue
    lines = raw.rstrip('\n').splitlines()
    if len(lines) != 1:
        raise SystemExit(f'index stage overlap for {path}')
    mode, blob, rest = lines[0].split(' ', 2)
    stage, recorded = rest.split('\t', 1)
    if stage != '0' or recorded != path:
        raise SystemExit(f'index stage/path mismatch for {path}')
    full = os.path.join(repo, path)
    if not os.path.isfile(full) or os.path.islink(full):
        raise SystemExit(f'worktree type mismatch for {path}')
    actual = subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', 'hash-object', '--', path], text=True, env=ENV).strip()
    if actual != blob:
        raise SystemExit(f'worktree blob mismatch for {path}')
    actual_mode = '100755' if stat.S_IXUSR & os.stat(full).st_mode else '100644'
    if actual_mode != mode:
        raise SystemExit(f'worktree mode mismatch for {path}')
    subprocess.run(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', 'diff-files', '--quiet', '--', path], check=True, env=ENV)
    print(f'{path}\t{blob}\t{mode}\tfile')
PY
}

projection_stage_records() {
  local lane="$1"
  "$PYTHON" - "$MATRIX" "$lane" <<'PY'
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import json
import sys
m = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8'))
lane = next(x for x in m['ordered_lanes'] if x['id'] == sys.argv[2])
paths = lane.get('semantic_delta', {}).get('owned_paths') or lane['owned_paths']
for path in paths:
    state = lane['stage_precondition']['paths'][path]
    print('\t'.join([path, state['blob'] or '-', state['mode'] or '-', state['type']]))
PY
}

apply_semantic_lane() {
  local lane="$1" record semantic_file projection_file
  local info=()
  semantic_file="$(producer_to_file semantic-records "$REPLAY_ROOT" semantic_records "$lane")"
  assert_semantic_records_file "$lane" "$semantic_file"
  while IFS= read -r record; do
    info[${#info[@]}]="$record"
  done < "$semantic_file"
  cleanup_temp_file "$semantic_file"
  test "${#info[@]}" -eq 3 || fail "semantic producer row count mismatch for $lane"
  local target="${info[0]-}" source_parent="${info[1]-}" path_blob="${info[2]-}"
  local paths=()
  IFS=$'\x1f' read -r -a paths <<< "$path_blob"
  test -n "$target" && test -n "$source_parent" || fail "semantic parent/child missing for $lane"
  test "${#paths[@]}" -gt 0 || fail "empty semantic path set for $lane"
  test "$(git_replay rev-parse "$target^1")" = "$source_parent" || fail "semantic source parent mismatch for $lane"
  DIRTY_PATHS=()
  before_mutation
  assert_declared_projection "$lane"
  local path old_blob old_mode old_kind new_blob new_mode new_kind target_line target_type
  projection_file="$(producer_to_file projection-records "$REPLAY_ROOT" projection_stage_records "$lane")"
  assert_projection_stage_records_file "$lane" "$projection_file"
  while IFS=$'\t' read -r path old_blob old_mode old_kind; do
    assert_declared_projection "$lane" "$path"
    target_line="$(git_replay ls-tree "$target" -- "$path")"
    if [ -z "$target_line" ]; then
      new_blob='-'
      new_mode='-'
      new_kind=absent
    else
      read -r new_mode target_type new_blob _ <<< "$target_line"
      test "$target_type" = blob || fail "semantic target type mismatch for $path"
      new_kind=file
      assert_source_blob "$target" "$path" "$new_blob"
    fi
    cas_path "$path" "$old_blob" "$old_mode" "$old_kind" "$new_blob" "$new_mode" "$new_kind"
  done < "$projection_file"
  cleanup_temp_file "$projection_file"
  assert_exact_staged "${paths[@]}"
  git_replay diff --cached --check -- "${paths[@]}"
  commit_staged "replay(task409): $lane semantic projection" - "${paths[@]}"
}

matrix_records() {
  local stage="$1"
  "$PYTHON" - "$MATRIX" "$stage" <<'PY'
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import json
import sys
m = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8'))
for row in m['live_overlap']['blob_matrix']:
    if sys.argv[2] == 'launcher' and row['launcher_mechanical']:
        print('\t'.join([row['path'], row['proxy_blob'] or '-', row['proxy_mode'] or '-', row['d3_launcher_blob'] or '-', row['d3_launcher_mode'] or '-']))
    if sys.argv[2] == 'live' and row['live_mechanical']:
        old_blob = row['d3_launcher_blob'] if row['launcher_mechanical'] else row['proxy_blob']
        old_mode = row['d3_launcher_mode'] if row['launcher_mechanical'] else row['proxy_mode']
        print('\t'.join([row['path'], old_blob or '-', old_mode or '-', row['80fe_live_blob'] or '-', row['80fe_live_mode'] or '-']))
PY
}

apply_matrix_stage() {
  local stage="$1" expected_patch expected_raw source_left target projection_lane
  if [ "$stage" = launcher ]; then
    source_left="$BASE"
    target="$LAUNCHER"
    projection_lane=launcher-semantic-projection
    expected_patch=cd1e6446174eca48b7bca2b263c332e0f71303b1
    expected_raw=5c9f76cd27ba4c4136f324926aab1f01f00e1033b21ee0dfb81da9ac3d016942
  else
    source_left="$LAUNCHER"
    target="$LIVE"
    projection_lane=live-proof-semantic-projection
    expected_patch=304ee69ee3b7753aa516ee86f3b3053d3f9ec97b
    expected_raw=12892436be96696fa5f0261e5c238b5aa82d46267b829b5e081896ab642dd1c3
  fi
  local rows=() record matrix_file
  matrix_file="$(producer_to_file matrix-records "$REPLAY_ROOT" matrix_records "$stage")"
  assert_matrix_records_file "$stage" "$matrix_file"
  while IFS= read -r record; do
    rows[${#rows[@]}]="$record"
  done < "$matrix_file"
  cleanup_temp_file "$matrix_file"
  test "${#rows[@]}" -gt 0 || fail "empty $stage matrix stage"
  local paths=() snapshots=() row path old_blob old_mode new_blob new_mode old_kind
  for row in "${rows[@]}"; do
    IFS=$'	' read -r path old_blob old_mode new_blob new_mode <<< "$row"
    paths+=("$path")
    snapshots+=("$row")
  done
  DIRTY_PATHS=()
  before_mutation
  assert_declared_projection "$projection_lane"
  for row in "${snapshots[@]}"; do
    IFS=$'	' read -r path old_blob old_mode new_blob new_mode <<< "$row"
    assert_declared_projection "$projection_lane" "$path"
    old_kind=file
    [ "$old_blob" = - ] && old_kind=absent
    [ "$old_mode" = - ] && old_mode=-
    [ "$new_blob" = - ] && fail "matrix target unexpectedly absent for $path"
    assert_source_blob "$target" "$path" "$new_blob"
    cas_path "$path" "$old_blob" "$old_mode" "$old_kind" "$new_blob" "$new_mode" file
  done
  assert_exact_staged "${paths[@]}"
  git_replay diff --cached --check -- "${paths[@]}"
  test "$(binary_patch_id "$source_left" "$target" "${paths[@]}")" = "$expected_patch" || fail "approved mechanical source patch-id mismatch for $stage"
  test "$(raw_patch_sha256 "$source_left" "$target" "${paths[@]}")" = "$expected_raw" || fail "approved mechanical source raw SHA mismatch for $stage"
  assert_cached_patch - "${paths[@]}"
  commit_staged "replay(task409): $stage semantic projection" - "${paths[@]}"
}


assert_stage_two_overlap() {
  "$PYTHON" - "$MATRIX" "$REPLAY" "$CURRENT_HEAD" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import json
import subprocess
import sys
m, repo, head = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8')), sys.argv[2], sys.argv[3]
def run(*args):
    return subprocess.check_output(['/usr/bin/git','--no-replace-objects','--no-lazy-fetch','--no-optional-locks','-C',repo,'-c','core.hooksPath=/dev/null','-c','protocol.allow=never',*args], text=True, env=ENV).strip()
rows = {r['path']: r for r in m['live_overlap']['blob_matrix']}
for path in m['live_overlap']['stage_two_required_d3_overlap_paths']:
    if run('rev-parse', f'{head}:{path}') != rows[path]['d3_launcher_blob']:
        raise SystemExit(f'd3 overlap mismatch for {path}')
if run('rev-parse', f'{head}:scripts/README.md') != m['live_overlap']['scripts_readme']['proxy_post_lane_blob']:
    raise SystemExit('README changed before separate merge')
PY
}

merge_scripts_readme() {
  local merged_blob parent
  before_mutation
  "$PYTHON" - "$REPLAY" "$README_TMP" "$MATRIX" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

from pathlib import Path
import hashlib
import json
import subprocess
import sys
repo, out, matrix = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
git = '/usr/bin/git'
def show(spec):
    return subprocess.check_output([git, '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', str(repo), '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', 'show', spec], env=ENV)
metadata = json.loads(read_stable_file(matrix, 'matrix source')[0].decode('utf-8'))
anchor_text = metadata['live_overlap']['scripts_readme']['section_anchor']
if not isinstance(anchor_text, str):
    raise SystemExit('README anchor metadata is not a string')
anchor = anchor_text.encode('utf-8')
if anchor != b'## Disposable Caddy proof renderer\n':
    raise SystemExit('README anchor metadata does not decode to the canonical LF anchor')
prefix = show('80fe3b68fb676a3b6589fce9aed79140bf37b667:scripts/README.md')
section = show('e3a2d2e662f2e606f318d35f4fccc63ba9738f7c:scripts/README.md')
if prefix.count(anchor) != 1 or section.count(anchor) != 1:
    raise SystemExit('README anchor count mismatch')
merged = prefix.split(anchor, 1)[0] + section[section.index(anchor):]
if len(merged) != 44854 or merged.count(b'\n') != 739:
    raise SystemExit('README shape mismatch')
if hashlib.sha256(merged).hexdigest() != '2a15d48344d3d00c9e6a0f95f1805ec41c251b8886487bb3b1935fdff70c2030':
    raise SystemExit('README SHA-256 mismatch')
out.write_bytes(merged)
PY
  test -f "$README_TMP"
  before_mutation
  merged_blob="$(git_replay hash-object -w -- "$README_TMP")"
  test "$merged_blob" = d74f0c1431901f83e736389395a122c48e521a32 || fail "README Git blob mismatch"
  cas_path scripts/README.md c2a31b8b58237551b698c64671a027da28ed84ff 100644 file "$merged_blob" 100644 file
  assert_exact_staged scripts/README.md
  git_replay diff --cached --check -- scripts/README.md
  parent="$CURRENT_HEAD"
  commit_staged 'replay(task409): reviewed scripts README merge' - scripts/README.md
}

assert_final_matrix() {
  "$PYTHON" - "$MATRIX" "$REPLAY" "$CURRENT_HEAD" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import hashlib
import json
import subprocess
import sys
m, repo, head = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8')), sys.argv[2], sys.argv[3]
def run(*args):
    return subprocess.check_output(['/usr/bin/git','--no-replace-objects','--no-lazy-fetch','--no-optional-locks','-C',repo,'-c','core.hooksPath=/dev/null','-c','protocol.allow=never',*args], text=True, env=ENV).strip()
for row in m['live_overlap']['blob_matrix']:
    path = row['path']
    actual = run('rev-parse', f'{head}:{path}')
    if actual != row['expected_final_blob']:
        raise SystemExit(f'final blob mismatch for {path}')
    tree_line = run('ls-tree', head, '--', path)
    if not tree_line.startswith(row['expected_final_mode'] + ' blob '):
        raise SystemExit(f'final mode/type mismatch for {path}')
readme = subprocess.check_output(['/usr/bin/git','--no-replace-objects','--no-lazy-fetch','--no-optional-locks','-C',repo,'-c','core.hooksPath=/dev/null','-c','protocol.allow=never','show',f'{head}:scripts/README.md'], env=ENV)
info = m['live_overlap']['scripts_readme']
if len(readme) != info['expected_bytes'] or readme.count(b'\n') != info['expected_lines']:
    raise SystemExit('final README shape mismatch')
if hashlib.sha256(readme).hexdigest() != info['expected_sha256']:
    raise SystemExit('final README SHA mismatch')
if run('rev-parse', f'{head}:scripts/README.md') != info['expected_git_blob']:
    raise SystemExit('final README blob mismatch')
PY
}

assert_forbidden_ancestry() {
  local bad_object ancestry_file
  local bad_objects=()
  ancestry_file="$(producer_to_file forbidden-ancestry "$REPLAY_ROOT" forbidden_ancestry_records)"
  assert_forbidden_ancestry_records_file "$ancestry_file"
  while IFS= read -r bad_object; do
    bad_objects[${#bad_objects[@]}]="$bad_object"
  done < "$ancestry_file"
  cleanup_temp_file "$ancestry_file"
  test "${#bad_objects[@]}" -gt 0 || fail "forbidden ancestry producer emitted no rows"
  bad_objects[${#bad_objects[@]}]="$REJECTED_AUTH_LEFT"
  bad_objects[${#bad_objects[@]}]="$REJECTED_AUTH_RIGHT"
  local bad rc
  for bad in "${bad_objects[@]}"; do
    set +e
    git_replay merge-base --is-ancestor "$bad" "$CURRENT_HEAD"
    rc=$?
    set -e
    test "$rc" -eq 1 || fail "forbidden ancestry $bad returned $rc, expected exact rc=1"
  done
}

assert_root_empty() {
  "$PYTHON" - "$REPLAY_ROOT" "$REPLAY_ROOT_DEVICE" "$REPLAY_ROOT_INODE" "$REPLAY_ROOT_UID" "$REPLAY_ROOT_MODE" "$REPLAY_ROOT_REALPATH" <<'PY'
import os
import stat
import sys
root, expected_device, expected_inode, expected_uid, expected_mode, expected_realpath = sys.argv[1:]
st = os.lstat(root)
if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
    raise SystemExit('replay root is not a non-symlink directory before rmdir')
if (str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')) != (expected_device, expected_inode, expected_uid, expected_mode):
    raise SystemExit('replay root lstat identity changed before rmdir')
if os.path.realpath(root) != expected_realpath or expected_realpath != root:
    raise SystemExit('replay root canonical identity changed before rmdir')
if os.listdir(root):
    raise SystemExit('replay root is not empty before rmdir')
PY
}


assert_final_root_cleanup_boundary() {
  assert_root_shape
  assert_worktree_separation
  assert_primary_pins
  test "$REPLAY_READY" -eq 0 || fail "replay checkout still marked ready before root removal"
  test -z "$CURRENT_HEAD" && test -z "$CURRENT_TREE" || fail "replay state remains bound before root removal"
  test "${#DIRTY_PATHS[@]}" -eq 0 || fail "dirty paths remain before root removal"
  assert_root_empty
}

assert_replay_preinit_state() {
  # Targeted regression smoke for the descriptor-created, pre-init child: it
  # must be present and bound, while no Git registry call is permitted yet.
  test "$REPLAY_ROOT_BOUND" -eq 1 || fail "pre-init smoke lost replay root binding"
  test "$REPLAY_CHECKOUT_PRESENT" -eq 1 || fail "pre-init smoke lost checkout presence"
  test "$REPLAY_CHECKOUT_BOUND" -eq 1 || fail "pre-init smoke lost checkout identity"
  test "$REPLAY_GIT_BOUND" -eq 0 || fail "pre-init smoke ran Git identity too early"
  test -d "$REPLAY" && test ! -e "$REPLAY/.git" || fail "pre-init smoke found Git metadata"
  assert_root_shape
  assert_worktree_separation
}

assert_replay_checkout_removed_state() {
  # Regression guard: checkout removal leaves the root bound for final rmdir,
  # but no child or Git identity may be consumed by later cleanup assertions.
  test "$REPLAY_ROOT_BOUND" -eq 1 || fail "removed-checkout smoke lost replay root binding"
  test "$REPLAY_CHECKOUT_PRESENT" -eq 0 || fail "removed-checkout smoke still marks child present"
  test "$REPLAY_CHECKOUT_BOUND" -eq 0 || fail "removed-checkout smoke still binds child identity"
  test "$REPLAY_GIT_BOUND" -eq 0 || fail "removed-checkout smoke still binds Git identity"
  test ! -e "$REPLAY" && test ! -L "$REPLAY" || fail "removed-checkout smoke found replay child"
  assert_root_shape
  assert_worktree_separation
  test "$REPLAY_CHECKOUT_PRESENT" -eq 0 || fail "removed-checkout smoke state drifted"
}

cleanup_success_only() {
  local path allowed item
  for path in "$@"; do
    allowed=0
    for item in "${CLEANUP_ALLOWLIST[@]}"; do
      [ "$path" = "$item" ] && allowed=1
    done
    test "$allowed" -eq 1 || fail "cleanup path is not allowlisted: $path"
    case "$path" in "$REPLAY_ROOT"/*) ;; *) fail "cleanup path escaped replay root: $path" ;; esac
    [ -e "$path" ] || [ -L "$path" ] || continue
    case "$path" in
      "$REPLAY")
        before_mutation
        "$RM" -rf -- "$path"
        REPLAY_READY=0
        CURRENT_HEAD=''
        CURRENT_TREE=''
        BOOTSTRAP_HEAD=''
        BOOTSTRAP_TREE=''
        DIRTY_PATHS=()
        REPLAY_CHECKOUT_PRESENT=0
        REPLAY_CHECKOUT_BOUND=0
        REPLAY_GIT_BOUND=0
        REPLAY_OBJECTS_BOUND=0
        REPLAY_INFO_BOUND=0
        REPLAY_ALTERNATES_BOUND=0
        assert_replay_checkout_removed_state
        ;;
      "$README_TMP") before_mutation; "$RM" -f -- "$path" ;;
      "$MATRIX_SNAPSHOT") before_mutation; "$RM" -f -- "$path"; MATRIX_BOUND=2 ;;
      *) fail "unexpected cleanup path: $path" ;;
    esac
  done
  test ! -e "$REPLAY" || fail 'replay checkout cleanup incomplete'
  test ! -e "$README_TMP" || fail 'README temp cleanup incomplete'
  test ! -e "$MATRIX_SNAPSHOT" || fail 'matrix snapshot cleanup incomplete'
  allowed=0
  for item in "${CLEANUP_ALLOWLIST[@]}"; do
    [ "$REPLAY_ROOT" = "$item" ] && allowed=1
  done
  test "$allowed" -eq 1 || fail 'replay root is not an explicit cleanup allowlist entry'
  assert_final_root_cleanup_boundary
  "$RMDIR" -- "$REPLAY_ROOT"
  REPLAY_ROOT_BOUND=0
  REPLAY_CHECKOUT_BOUND=0
  REPLAY_CHECKOUT_PRESENT=0
  REPLAY_GIT_BOUND=0
}

cleanup_clean_primary_success_only() {
  local allowed item
  test "$CLEAN_PRIMARY_ROOT_BOUND" -eq 1 || fail 'clean-primary root is not bound for cleanup'
  allowed=0
  for item in "${CLEAN_PRIMARY_CLEANUP_ALLOWLIST[@]}"; do
    [ "$CLEAN_PRIMARY_ROOT" = "$item" ] && allowed=1
  done
  test "$allowed" -eq 1 || fail 'clean-primary cleanup path is not allowlisted'
  assert_source_binding
  assert_clean_primary_state
  assert_worktree_separation
  "$PYTHON" - "$CLEAN_PRIMARY_ROOT" "$CLEAN_PRIMARY_ROOT_DEVICE" "$CLEAN_PRIMARY_ROOT_INODE" "$CLEAN_PRIMARY_ROOT_UID" "$CLEAN_PRIMARY_ROOT_MODE" "$CLEAN_PRIMARY_ROOT_REALPATH" "$CLEAN_PRIMARY" <<'PY'
import os
import stat
import sys
root, expected_device, expected_inode, expected_uid, expected_mode, expected_realpath, repository = sys.argv[1:]
st = os.lstat(root)
if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(root) != expected_realpath or expected_realpath != root:
    raise SystemExit('clean-primary root identity changed before cleanup')
if (str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')) != (expected_device, expected_inode, expected_uid, expected_mode):
    raise SystemExit('clean-primary root lstat changed before cleanup')
if set(os.listdir(root)) != {os.path.basename(repository)}:
    raise SystemExit('unknown clean-primary cleanup artifact present')
if os.path.islink(repository) or not os.path.isdir(repository) or os.path.realpath(repository) != repository:
    raise SystemExit('clean-primary repository changed before cleanup')
PY
  "$RM" -rf -- "$CLEAN_PRIMARY_ROOT"
  test ! -e "$CLEAN_PRIMARY_ROOT" || fail 'clean-primary cleanup incomplete'
  CLEAN_PRIMARY_ROOT_BOUND=0
  CLEAN_PRIMARY_REPOSITORY_BOUND=0
  CLEAN_PRIMARY_BOUND=0
}


# Static manifest validation is read-only. SOURCE may be noisy; the clean-primary copy is validated separately.
static_validate_matrix() {
  local repository="$1"
  "$PYTHON" - "$MATRIX" "$repository" "$MARKDOWN" "$MATRIX_EXPECTED_BINDING_SHA256" <<'PY'
from __future__ import annotations
import re

def strict_single_record_lf(raw, label='record'):
    """Parse one non-empty record with exactly one terminal LF."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must contain exactly one LF-framed record')
    record = raw[:-1]
    if not record or b'\n' in record:
        raise SystemExit(f'{label} must contain exactly one non-empty record')
    return record


def restore_command_substitution_lf(value, label='record'):
    """Put back the LF Bash command substitution removes before parsing."""
    if not isinstance(value, str) or not value or '\r' in value or '\n' in value:
        raise SystemExit(f'{label} command-substitution value is not one record')
    return strict_single_record_lf(value.encode('utf-8') + b'\n', label)


def strict_record_lines(raw, label='records'):
    """Parse a non-empty LF-framed stream without CR or blank rows."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must be LF-framed with no blank records')
    rows = raw[:-1].split(b'\n')
    if any(not row for row in rows):
        raise SystemExit(f'{label} contains an empty record')
    return rows


def strict_git_commit(value, label='Git commit'):
    """Require one complete lowercase SHA-1 commit token."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex')
    return value


def strict_git_parent_endpoint(value, label='Git parent endpoint'):
    """Require one complete lowercase SHA-1 token with one parent suffix."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}\^', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex^')
    return value


def strict_inclusive_git_range(record, label='Git range'):
    """Bind an inclusive notation to its separately validated endpoints."""
    if not isinstance(record, dict):
        raise SystemExit(f'{label} is not an object')
    left = strict_git_parent_endpoint(record.get('left'), f'{label}.left')
    right = strict_git_commit(record.get('right'), f'{label}.right')
    notation = record.get('notation')
    if (not isinstance(notation, str)
            or re.fullmatch(r'[0-9a-f]{40}\^\.\.[0-9a-f]{40}', notation) is None):
        raise SystemExit(f'{label}.notation is not lowercase 40hex^..40hex')
    if notation != f'{left}..{right}':
        raise SystemExit(f'{label}.notation does not match its validated endpoints')
    return left, right, notation


def strict_git_commit_range(value, label='Git commit range'):
    """Validate a two-commit range before either endpoint is used."""
    if (not isinstance(value, str)
            or re.fullmatch(r'[0-9a-f]{40}\.\.[0-9a-f]{40}', value) is None):
        raise SystemExit(f'{label} is not lowercase 40hex..40hex')
    left, right = value.split('..')
    return strict_git_commit(left, f'{label}.left'), strict_git_commit(right, f'{label}.right')

ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file', limit=2 * 1024 * 1024):
    """Read bounded bytes from one descriptor after binding its path."""
    path = os.fspath(path)
    if (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise SystemExit(f'{label} read limit is invalid')
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        # Keep owner/mode/link/size policy and add nanosecond timestamps. The
        # type check remains separate because S_IMODE intentionally excludes it.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def parent_identity(st):
        # Directory size/timestamps change for unrelated child churn. Bind only
        # identity, owner, and mode here; the held grandparent binds its name.
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)

    # Open the parent relative to a held grandparent. The final parent-name
    # check below therefore rejects replacement of the parent directory itself;
    # the child bytes are never reopened through a pathname.
    if parent == os.path.sep:
        grandparent_fd = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_bound_before = parent_pre
    else:
        grandparent = os.path.dirname(parent)
        grandparent_name = os.path.basename(parent)
        grandparent_pre = os.lstat(grandparent)
        if (not stat.S_ISDIR(grandparent_pre.st_mode)
                or stat.S_ISLNK(grandparent_pre.st_mode)
                or os.path.realpath(grandparent) != grandparent):
            raise SystemExit(f'{label} grandparent is not a canonical directory')
        grandparent_fd = os.open(
            grandparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            parent_bound_before = os.stat(
                grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
            )
            if parent_identity(parent_bound_before) != expected_parent:
                raise SystemExit(f'{label} parent binding changed before open')
            parent_fd = os.open(
                grandparent_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=grandparent_fd,
            )
        except BaseException:
            os.close(grandparent_fd)
            raise

    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        child_pre = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(child_pre.st_mode) or child_pre.st_nlink != 1:
            raise SystemExit(f'{label} is not a regular single-link file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            if file_identity(child_pre) != file_identity(first):
                raise SystemExit(f'{label} child identity changed before descriptor read')
            if first.st_size < 0 or first.st_size > limit:
                raise SystemExit(f'{label} exceeds bounded read limit')

            import hashlib

            def read_pass(keep_bytes):
                chunks = [] if keep_bytes else None
                digest = hashlib.sha256()
                total = 0
                while True:
                    # The +1 sentinel makes an oversized read fail before its
                    # chunk can be retained, without allocating unbounded data.
                    request = min(1024 * 1024, limit - total + 1)
                    if request <= 0:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    chunk = os.read(fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SystemExit(f'{label} exceeds bounded read limit')
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                return (b''.join(chunks) if chunks is not None else None), digest.digest(), total

            raw, first_digest, first_count = read_pass(True)
            after_first = os.fstat(fd)
            if file_identity(first) != file_identity(after_first):
                raise SystemExit(f'{label} descriptor changed while reading')
            if first_count != first.st_size:
                raise SystemExit(f'{label} byte count disagrees with descriptor size')

            # Re-read only through the same held descriptor. The first pass is
            # the accepted byte source; this bounded digest pass catches an
            # in-place overwrite even when inode and size are unchanged.
            os.lseek(fd, 0, os.SEEK_SET)
            _unused, second_digest, second_count = read_pass(False)
            after_second = os.fstat(fd)
            if file_identity(first) != file_identity(after_second):
                raise SystemExit(f'{label} descriptor changed after verification')
            if second_count != first.st_size or second_digest != first_digest:
                raise SystemExit(f'{label} bytes changed while being read')

            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
            if parent == os.path.sep:
                parent_bound_after = parent_second
            else:
                parent_bound_after = os.stat(
                    grandparent_name, dir_fd=grandparent_fd, follow_symlinks=False
                )
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(grandparent_fd)

    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent descriptor identity changed while reading')
    if parent_identity(parent_bound_before) != parent_identity(parent_bound_after):
        raise SystemExit(f'{label} parent path binding changed while reading')
    if file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if first_count != final.st_size:
        raise SystemExit(f'{label} byte count disagrees with final size')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return raw, first

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

matrix, repo, markdown, expected_binding = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), sys.argv[4]
raw_matrix, _matrix_stat = read_stable_file(matrix, 'matrix source')

def normalized_matrix_bytes(raw, token):
    normalized = raw.replace(token.encode('ascii'), b'0' * 64)
    for key in (b'"shell_sha256": "', b'"driver_shell_sha256": "', b'"expected_body_sha256": "'):
        normalized = re.sub(re.escape(key) + rb'[0-9a-f]{64}(?=")', lambda match: match.group(0)[:len(key)] + b'0' * 64, normalized)
    return normalized

data = json.loads(raw_matrix)
execution_driver = data['execution_driver']
validation_contract = data['validation_contract']
for identity_key in ('matrix_identity', 'replay_root_identity', 'clean_primary_storage_identity'):
    if execution_driver.get(identity_key) != validation_contract.get(identity_key):
        raise SystemExit(f'duplicated identity contract mismatch: {identity_key}')
if execution_driver.get('source_of_truth') != '/execution_driver/shell':
    raise SystemExit('execution driver source-of-truth mismatch')
stale_scripts = execution_driver.get('non_authoritative_standalone_scripts')
if not isinstance(stale_scripts, list) or not any(item.get('path') == '/tmp/' + 'hermternal-task409-approved-driver.sh' and 'non-authoritative' in item.get('status', '') for item in stale_scripts):
    raise SystemExit('stale standalone driver policy is missing')
fresh_requirement = execution_driver.get('fresh_shell_requirement')
if not isinstance(fresh_requirement, dict) or fresh_requirement.get('required_before_execution') is not True:
    raise SystemExit('fresh shell extraction requirement is missing')
identity = execution_driver['matrix_identity']
if identity['source_path'] != str(matrix):
    raise SystemExit('matrix source-path metadata mismatch')
if identity['expected_normalized_sha256'] != expected_binding:
    raise SystemExit('matrix identity token mismatch')
if hashlib.sha256(normalized_matrix_bytes(raw_matrix, expected_binding)).hexdigest() != expected_binding:
    raise SystemExit('matrix source normalized SHA-256 mismatch')
shell_bytes = execution_driver['shell'].encode('utf-8')
shell_sha = hashlib.sha256(shell_bytes).hexdigest()
if execution_driver['shell_sha256'] != shell_sha or validation_contract['driver_shell_sha256'] != shell_sha:
    raise SystemExit('driver shell hash metadata mismatch')
expected_shell_metadata = {'body_bytes': len(shell_bytes), 'body_lines': len(shell_bytes.splitlines()), 'terminal_byte_hex': shell_bytes[-1:].hex()}
if execution_driver.get('shell_size_metadata') != expected_shell_metadata or validation_contract.get('shell_size_metadata') != expected_shell_metadata:
    raise SystemExit('numeric shell metadata mismatch')
if validation_contract.get('driver_shell_body_bytes') != len(shell_bytes) or validation_contract.get('driver_shell_body_lines') != len(shell_bytes.splitlines()):
    raise SystemExit('duplicated numeric shell size metadata mismatch')
extraction = data['execution_driver']['markdown_fence_extraction']
markdown_bytes, _markdown_stat = read_stable_file(markdown, 'Markdown source')
full_ids = set(re.findall(r'(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])', (raw_matrix + markdown_bytes).decode('utf-8').lower()))
short_ref = re.compile(r'(?<![0-9a-f])[0-9a-f]{7,39}(?![0-9a-f])')
for label, payload in (('JSON', raw_matrix.decode('utf-8')), ('Markdown', markdown_bytes.decode('utf-8'))):
    for match in short_ref.finditer(payload.lower()):
        token = match.group(0)
        if any(value.startswith(token) for value in full_ids):
            raise SystemExit(f'abbreviated exact reference in {label}: {token}')
section_heading = extraction['section_heading'].encode('utf-8')
section_start = markdown_bytes.index(section_heading)
opening = extraction['opening_fence'].encode('ascii')
closing = extraction['closing_fence'].encode('ascii')
opening_start = markdown_bytes.index(opening, section_start + len(section_heading))
body_start = opening_start + len(opening)
closing_start = markdown_bytes.index(closing, body_start)
body = markdown_bytes[body_start:closing_start]
if body != shell_bytes:
    raise SystemExit('Markdown direct-fence body differs from JSON shell')
if len(body) != extraction['expected_body_bytes'] or hashlib.sha256(body).hexdigest() != extraction['expected_body_sha256']:
    raise SystemExit('Markdown direct-fence body metadata mismatch')
if extraction['expected_body_bytes'] != len(shell_bytes) or extraction.get('expected_body_lines') != len(shell_bytes.splitlines()):
    raise SystemExit('Markdown and JSON shell size metadata mismatch')
if body[-1:].hex() != extraction['expected_terminal_byte_hex'] or shell_bytes[-1:].hex() != extraction['expected_terminal_byte_hex']:
    raise SystemExit('driver terminal-byte metadata mismatch')
ordered_steps_header = b'| Order | Step | Boundary | Gate |'
ordered_steps_start = markdown_bytes.index(ordered_steps_header)
ordered_steps_lines = markdown_bytes[ordered_steps_start:].splitlines()
parsed_md_steps = []
for line in ordered_steps_lines[2:]:
    if not line.startswith(b'| '):
        break
    fields = line.split(b'|')
    if len(fields) != 6 or not fields[1].strip().isdigit():
        break
    parsed_md_steps.append({
        'order': int(fields[1].strip()),
        'gate': fields[4].strip().decode('utf-8'),
    })
json_steps = data['execution_driver']['ordered_steps']
if len(parsed_md_steps) != 21 or [row['order'] for row in parsed_md_steps] != list(range(1, 22)):
    raise SystemExit('Markdown ordered-step table must contain exactly 21 ordered rows')
if len(json_steps) != 21 or [row['order'] for row in json_steps] != list(range(1, 22)):
    raise SystemExit('JSON ordered-step metadata must contain exactly 21 ordered rows')
if [row['gate'] for row in parsed_md_steps] != [row['gate'] for row in json_steps]:
    raise SystemExit('Markdown and JSON ordered-step gate strings differ')
appendix_metadata = validation_contract['markdown_parity_appendix']
appendix_heading = appendix_metadata['section_heading'].encode('utf-8')
appendix_opening = appendix_metadata['opening_fence'].encode('ascii')
appendix_closing = appendix_metadata['closing_fence'].encode('ascii')
appendix_heading_start = markdown_bytes.index(appendix_heading)
appendix_opening_start = markdown_bytes.index(appendix_opening, appendix_heading_start + len(appendix_heading))
appendix_body_start = appendix_opening_start + len(appendix_opening)
appendix_closing_start = markdown_bytes.index(appendix_closing, appendix_body_start)
appendix = json.loads(markdown_bytes[appendix_body_start:appendix_closing_start].decode('utf-8'))
target_mirrors = []
changed_mirrors = []
def collect_mirrors(node, pointer=''):
    if isinstance(node, dict):
        if 'target_states' in node:
            target_mirrors.append({'json_pointer': pointer or '/', 'changed_paths': node.get('changed_paths', []), 'target_states': node['target_states']})
        if 'changed_paths' in node:
            changed_mirrors.append({'json_pointer': pointer or '/', 'changed_paths': node['changed_paths']})
        for key, value in node.items():
            child = f'{pointer}/{key}' if pointer else f'/{key}'
            collect_mirrors(value, child)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            child = f'{pointer}/{index}' if pointer else f'/{index}'
            collect_mirrors(value, child)
collect_mirrors(data)
expected_appendix = {'target_states': target_mirrors, 'historical_changed_paths': changed_mirrors}
if appendix != expected_appendix:
    raise SystemExit('Markdown target-state/changed-path mirror content mismatch')
if appendix_metadata['target_state_entry_count'] != len(target_mirrors) or appendix_metadata['target_state_path_count'] != sum(len(row['target_states']) for row in target_mirrors):
    raise SystemExit('Markdown target-state mirror counts mismatch')
if appendix_metadata['historical_changed_path_entry_count'] != len(changed_mirrors) or appendix_metadata['historical_changed_path_count'] != sum(len(row['changed_paths']) for row in changed_mirrors):
    raise SystemExit('Markdown historical changed-path mirror counts mismatch')

git = '/usr/bin/git'
HEX = re.compile(r'^[0-9a-f]{40}$')

def run(*args, check=True, input_bytes=None):
    p = subprocess.run([git, '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', *args], input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    if check and p.returncode:
        raise SystemExit(f'Git command failed ({p.returncode}): {args!r}: {p.stderr.decode(errors="replace")}')
    return p

def out(*args):
    return run(*args).stdout.decode().strip()
def assert_object_closure():
    if out('rev-parse', '--show-object-format') != 'sha1':
        raise SystemExit('repository object format is not SHA-1')
    if out('rev-parse', '--is-shallow-repository') != 'false':
        raise SystemExit('repository is shallow')
    git_dir = Path(out('rev-parse', '--absolute-git-dir'))
    if os.path.realpath(git_dir) != str(git_dir):
        raise SystemExit('repository Git directory is not canonical')
    forbidden = (
        git_dir / 'shallow', git_dir / 'info' / 'grafts',
        git_dir / 'refs' / 'replace', git_dir / 'objects' / 'info' / 'alternates',
        git_dir / 'objects' / 'info' / 'http-alternates',
    )
    if any(path.exists() or path.is_symlink() for path in forbidden):
        raise SystemExit('repository contains forbidden shallow, graft, replacement, or alternate metadata')
    packed_refs = git_dir / 'packed-refs'
    if packed_refs.exists() and b'refs/replace/' in packed_refs.read_bytes():
        raise SystemExit('repository contains packed replacement refs')
    pack_dir = git_dir / 'objects' / 'pack'
    if pack_dir.exists() and (pack_dir.is_symlink() or os.path.realpath(pack_dir) != str(pack_dir)):
        raise SystemExit('repository pack directory is not canonical')
    if pack_dir.is_dir():
        for directory, names, files in os.walk(pack_dir, topdown=True, followlinks=False):
            names[:] = sorted(names)
            files.sort()
            if any(os.path.islink(os.path.join(directory, name)) for name in names):
                raise SystemExit('repository pack metadata contains a symlinked directory')
            if any(name.endswith('.promisor') for name in files):
                raise SystemExit('repository contains promisor pack metadata')
    config = run('config', '--local', '--get-regexp', r'^(extensions\.partialClone|remote\..*|protocol\..*\.allow)$', check=False)
    for line in config.stdout.decode().splitlines():
        key, _, value = line.partition(' ')
        if key.lower() == 'extensions.partialclone' or key.lower().endswith('.promisor') or key.lower().endswith('.vcs'):
            raise SystemExit('repository contains partial-clone, promisor, or custom-helper configuration')
        if value.strip().lower() not in ('never', ''):
            raise SystemExit('repository contains an unsafe protocol transport policy')
    fsck = run('fsck', '--full', '--strict', '--no-reflogs', '--no-progress')
    if fsck.returncode != 0:
        raise SystemExit('strict repository fsck failed')
    missing = run('rev-list', '--objects', '--all', '--missing=error')
    if missing.returncode != 0:
        raise SystemExit('repository object closure is incomplete')
    expected_by_key = {
        'commit': 'commit', 'parent': 'commit', 'parents': 'commit',
        'child': 'commit', 'tree': 'tree', 'blob': 'blob',
    }
    object_ids = {}
    def collect(node, key=None):
        if isinstance(node, dict):
            for child_key, child in node.items():
                collect(child, child_key)
        elif isinstance(node, list):
            for child in node:
                collect(child, key)
        elif isinstance(node, str) and re.fullmatch(r'[0-9a-f]{40}', node) and key in expected_by_key:
            object_ids[node] = expected_by_key[key]
    collect(data)
    for object_id, expected_type in sorted(object_ids.items()):
        actual = out('cat-file', '-t', object_id)
        if actual != expected_type:
            raise SystemExit(f'explicit object type mismatch: {object_id}: {actual} != {expected_type}')

assert_object_closure()

def oid(value, kind, label, missing=False):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise SystemExit(f'{label}: expected full lowercase ID, got {value!r}')
    p = run('cat-file', '-t', value, check=False)
    actual = p.stdout.decode().strip() if p.returncode == 0 else 'missing'
    if missing and actual == 'missing':
        return
    if actual != kind:
        raise SystemExit(f'{label}: expected {kind}, got {actual} for {value}')

def changed(commit):
    return set(out('diff-tree', '--root', '--no-commit-id', '--name-only', '-r', commit).splitlines())

def tree_state(ref, path):
    raw = out('ls-tree', ref, '--', path)
    if not raw:
        return {'blob': None, 'mode': None, 'type': 'absent'}
    lines = raw.splitlines()
    if len(lines) != 1:
        raise SystemExit(f'ambiguous tree state for {ref}:{path}')
    meta, recorded = lines[0].split('\t', 1)
    if recorded != path:
        raise SystemExit(f'tree path mismatch for {ref}:{path}')
    mode, kind, blob = meta.split()
    return {'blob': blob if kind == 'blob' else None, 'mode': mode, 'type': 'file' if kind == 'blob' else kind}

def patch_id(left, right, paths):
    raw = run('diff', '--binary', '--full-index', '--no-ext-diff', '--no-textconv', left, right, '--', *paths).stdout
    if not raw:
        raise SystemExit(f'empty binary patch: {left}..{right} {paths!r}')
    p = subprocess.run([git, '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-c', 'protocol.allow=never', 'patch-id', '--stable'], input=raw, stdout=subprocess.PIPE, check=True, env=ENV)
    return p.stdout.decode().split()[0], raw

def validate_commit(c, label, require_target_states=False):
    commit = c['commit']
    oid(commit, 'commit', label + '.commit')
    parents = out('rev-list', '--parents', '-n', '1', commit).split()[1:]
    if parents != c['parents']:
        raise SystemExit(f'{label}: parent mismatch')
    if out('rev-parse', f'{commit}^{{tree}}') != c['tree']:
        raise SystemExit(f'{label}: tree mismatch')
    changed_paths = set(c.get('changed_paths', []))
    if changed(commit) != changed_paths:
        raise SystemExit(f'{label}: exact changed-path scope mismatch')
    if require_target_states:
        states = c.get('target_states')
        if not isinstance(states, dict) or set(states) != changed_paths:
            raise SystemExit(f'{label}: exact target-state scope mismatch')
        for path in c['changed_paths']:
            expected = states[path]
            if expected.get('tree') != c['tree']:
                raise SystemExit(f'{label}.{path}: target tree binding mismatch')
            actual = tree_state(commit, path)
            for key in ('blob', 'mode', 'type'):
                if actual.get(key) != expected.get(key):
                    raise SystemExit(f'{label}.{path}: target {key} mismatch')
            if expected['type'] == 'file':
                oid(expected['blob'], 'blob', f'{label}.{path}.target_blob')
    if len(parents) == 1 and c.get('stable_patch_id'):
        actual, _ = patch_id(parents[0], commit, c['changed_paths'])
        if actual != c['stable_patch_id']:
            raise SystemExit(f'{label}: stable patch-id mismatch')

if out('rev-parse', 'origin/dev') != data['base']['commit'] or data['base']['commit'] != '729f2613af2b78d58b07918478e9102d5716f367':
    raise SystemExit('base/origin/dev mismatch')
if out('rev-parse', 'origin/main') != data['base']['protected_main_commit']:
    raise SystemExit('origin/main mismatch')
oid(data['base']['commit'], 'commit', 'base.commit')
oid(data['base']['tree'], 'tree', 'base.tree')
oid(data['base']['protected_main_commit'], 'commit', 'protected_main.commit')
if out('rev-parse', f'{data["base"]["commit"]}^{{tree}}') != data['base']['tree']:
    raise SystemExit('base tree mismatch')

stable_ids = []
for lane in data['ordered_lanes']:
    name = lane['id']
    r = lane.get('range')
    if r:
        range_left, range_right, notation = strict_inclusive_git_range(
            r, f'{name}.range')
        commits = out('rev-list', '--reverse', notation).split()
        listed = [c['commit'] for c in r['source_commits']]
        if commits != listed or len(commits) != r['count']:
            raise SystemExit(f'{name}: inclusive range mismatch')
        if int(out('rev-list', '--merges', '--count', notation)) != r['merge_commit_count']:
            raise SystemExit(f'{name}: merge count mismatch')
        union = set()
        for c in r['source_commits']:
            validate_commit(c, f'{name}.{c["commit"]}', require_target_states=True)
            union.update(c['changed_paths'])
            stable_ids.append(c['stable_patch_id'])
        if union != set(r['path_allowlist']) or len(union) != len(r['path_allowlist']):
            raise SystemExit(f'{name}: range path scope mismatch')
        actual, _ = patch_id(range_left, range_right, r['path_allowlist'])
        if actual != r['cumulative_stable_patch_id']:
            raise SystemExit(f'{name}: cumulative patch-id mismatch')
        stable_ids.append(r['cumulative_stable_patch_id'])
    for key in ('source_commit', 'intermediate_checkpoint'):
        c = lane.get(key)
        if c:
            validate_commit(c, f'{name}.{key}')
            stable_ids.append(c['stable_patch_id'])
    sd = lane.get('semantic_delta')
    if sd:
        oid(sd['parent'], 'commit', f'{name}.semantic.parent')
        oid(sd['child'], 'commit', f'{name}.semantic.child')
        oid(sd['parent_tree'], 'tree', f'{name}.semantic.parent_tree')
        oid(sd['child_tree'], 'tree', f'{name}.semantic.child_tree')
        if out('rev-parse', f"{sd['parent']}^{{tree}}") != sd['parent_tree']:
            raise SystemExit(f'{name}: semantic parent tree binding mismatch')
        if out('rev-parse', f"{sd['child']}^{{tree}}") != sd['child_tree']:
            raise SystemExit(f'{name}: semantic child tree binding mismatch')
        parents = out('rev-list', '--parents', '-n', '1', sd['child']).split()[1:]
        if parents != sd['child_parents']:
            raise SystemExit(f'{name}: semantic child parent mismatch')
        if changed(sd['child']) != set(sd['delta_paths']):
            raise SystemExit(f'{name}: semantic delta scope mismatch')
        actual, _ = patch_id(sd['parent'], sd['child'], sd['delta_paths'])
        if actual != sd['stable_patch_id']:
            raise SystemExit(f'{name}: semantic patch-id mismatch')
        stable_ids.append(sd['stable_patch_id'])

    if name in {
        'renderer-lifecycle', 'authentication-semantic-delta', 'fixture-registry-authority',
        'dependency-audit-correction', 'swift-parity-correction',
        'launcher-semantic-projection', 'live-proof-semantic-projection',
    }:
        source_state = lane.get('source_parent_state')
        stage_state = lane.get('stage_precondition')
        if not source_state or not stage_state:
            raise SystemExit(f'{name}: missing declared source-parent/stage state maps')
        source_paths = set(source_state['paths'])
        expected_path_list = lane.get('semantic_delta', {}).get('owned_paths') or lane.get('owned_paths') or lane.get('projection_paths')
        expected_paths = set(expected_path_list)
        if source_paths != expected_paths or set(stage_state['paths']) != expected_paths:
            raise SystemExit(f'{name}: declared projection state path scope mismatch')
        source_tree = out('rev-parse', f"{source_state['commit']}^{{tree}}")
        if source_tree != source_state['tree']:
            raise SystemExit(f'{name}: declared source-parent tree mismatch')
        for path, record in source_state['paths'].items():
            if record.get('tree') != source_state['tree']:
                raise SystemExit(f'{name}.{path}: source-parent path tree mismatch')
            actual = tree_state(source_state['commit'], path)
            if any(actual.get(key) != record.get(key) for key in ('blob', 'mode', 'type')):
                raise SystemExit(f'{name}.{path}: source-parent blob/mode/type mismatch')
            if record['type'] == 'file':
                oid(record['blob'], 'blob', f'{name}.{path}.source_parent_blob')
        for path, record in stage_state['paths'].items():
            tree_commit = record.get('tree_commit')
            if not isinstance(tree_commit, str) or len(tree_commit) != 40:
                raise SystemExit(f'{name}.{path}: stage tree commit missing')
            stage_tree = out('rev-parse', f"{tree_commit}^{{tree}}")
            if stage_tree != record.get('tree'):
                raise SystemExit(f'{name}.{path}: stage tree mismatch')
            actual = tree_state(tree_commit, path)
            if any(actual.get(key) != record.get(key) for key in ('blob', 'mode', 'type')):
                raise SystemExit(f'{name}.{path}: stage blob/mode/type mismatch')
            if record['type'] == 'file':
                oid(record['blob'], 'blob', f'{name}.{path}.stage_blob')
    oracle = lane.get('rehearsal_oracle')
    if oracle:
        validate_commit(oracle, f'{name}.rehearsal_oracle')
        stable_ids.append(oracle['stable_patch_id'])
    audit = lane.get('source_ancestry_audit')
    if audit:
        audit_left, audit_right, notation = strict_inclusive_git_range(
            audit, f'{name}.ancestry')
        commits = out('rev-list', '--reverse', notation).split()
        listed = [c['commit'] for c in audit['source_commits']]
        if commits != listed or len(commits) != audit['count']:
            raise SystemExit(f'{name}: ancestry audit range mismatch')
        if int(out('rev-list', '--merges', '--count', notation)) != audit['merge_commit_count']:
            raise SystemExit(f'{name}: ancestry audit merge count mismatch')
        union = set()
        for c in audit['source_commits']:
            validate_commit(c, f'{name}.audit.{c["commit"]}')
            union.update(c['changed_paths'])
            stable_ids.append(c['stable_patch_id'])
        if union != set(audit['path_allowlist']):
            raise SystemExit(f'{name}: ancestry audit path scope mismatch')
        actual, _ = patch_id(audit_left, audit_right, audit['path_allowlist'])
        if actual != audit['cumulative_stable_patch_id']:
            raise SystemExit(f'{name}: ancestry audit cumulative patch-id mismatch')
        stable_ids.append(audit['cumulative_stable_patch_id'])

# A source ancestry audit can repeat a patch ID already recorded by its source_commit.
# Duplicate application is rejected by assert_unique_patch_id in the replay transaction;
# here require uniqueness inside every independently executable source sequence.
for lane in data['ordered_lanes']:
    for key in ('range', 'source_ancestry_audit'):
        sequence = lane.get(key)
        if sequence:
            sequence_ids = [c['stable_patch_id'] for c in sequence['source_commits']]
            if len(sequence_ids) != len(set(sequence_ids)):
                raise SystemExit(f"{lane['id']}: duplicate stable patch ID inside executable sequence")

for lane_id in ('launcher-semantic-projection', 'live-proof-semantic-projection'):
    lane = next(x for x in data['ordered_lanes'] if x['id'] == lane_id)
    left, right = lane['projection_parent'], lane['source_commit']['commit']
    actual, raw = patch_id(left, right, lane['projection_paths'])
    if actual != lane['source_commit']['approved_scoped_stable_patch_id']:
        raise SystemExit(f'{lane_id}: approved scoped patch-id mismatch')
    if hashlib.sha256(raw).hexdigest() != lane['source_commit']['approved_scoped_raw_sha256']:
        raise SystemExit(f'{lane_id}: approved scoped raw SHA mismatch')
    actual, raw = patch_id(left, right, lane['mechanical_paths'])
    if actual != lane['source_commit']['approved_mechanical_scoped_stable_patch_id']:
        raise SystemExit(f'{lane_id}: mechanical patch-id mismatch')
    if hashlib.sha256(raw).hexdigest() != lane['source_commit']['approved_mechanical_scoped_raw_sha256']:
        raise SystemExit(f'{lane_id}: mechanical raw SHA mismatch')

for obj in data['historical_compatibility_objects']:
    oid(obj['commit'], 'commit', 'historical.commit')
    oid(obj['tree'], 'tree', 'historical.tree')
for value in data['forbidden_ancestry']['commits'] + data['forbidden_ancestry']['raw_semantic_source_commits']:
    oid(value, 'commit', 'forbidden.commit')
authentication_left, authentication_right = strict_git_commit_range(
    data['forbidden_ancestry']['authentication_range'], 'rejected-auth.range')
for endpoint in (authentication_left, authentication_right):
    oid(endpoint, 'commit', 'rejected-auth.endpoint')
for row in data['live_overlap']['blob_matrix']:
    for key in ('base_blob', 'proxy_blob', 'd3_launcher_blob', 'f54_blob', '80fe_live_blob'):
        if row[key]:
            oid(row[key], 'blob', f'{row["path"]}.{key}')
    for key in ('base_mode', 'proxy_mode', 'd3_launcher_mode', 'f54_mode', '80fe_live_mode', 'expected_final_mode'):
        if row[key] is not None and row[key] not in ('100644', '100755'):
            raise SystemExit(f'{row["path"]}: invalid mode')
    oid(row['expected_final_blob'], 'blob', f'{row["path"]}.expected_final', missing=row['path'] == 'scripts/README.md')

lo = data['live_overlap']
if len(lo['launcher_paths']) != 11 or len(lo['live_paths']) != 22 or len(lo['union_paths']) != 29 or len(lo['intersection_paths']) != 4:
    raise SystemExit('11/22/29/4 cardinality mismatch')
if set(lo['union_paths']) != set(lo['launcher_paths']) | set(lo['live_paths']):
    raise SystemExit('union path mismatch')
if set(lo['intersection_paths']) != set(lo['launcher_paths']) & set(lo['live_paths']):
    raise SystemExit('intersection path mismatch')
if len(set(row['path'] for row in lo['blob_matrix'])) != 29:
    raise SystemExit('duplicate blob-matrix path')
if set(lo['launcher_mechanical_paths']) != set(lo['launcher_paths']) - {'scripts/README.md'}:
    raise SystemExit('launcher mechanical mismatch')
if set(lo['live_mechanical_paths']) != set(lo['live_paths']) - {'scripts/README.md'}:
    raise SystemExit('live mechanical mismatch')
if set(lo['stage_two_required_d3_overlap_paths']) != set(lo['intersection_paths']) - {'scripts/README.md'}:
    raise SystemExit('stage-two d3 overlap mismatch')

anchor_text = data['live_overlap']['scripts_readme']['section_anchor']
if not isinstance(anchor_text, str):
    raise SystemExit('README anchor metadata is not a string')
anchor = anchor_text.encode('utf-8')
if anchor != b'## Disposable Caddy proof renderer\n':
    raise SystemExit('README anchor metadata does not decode to the canonical LF anchor')
prefix = run('show', '80fe3b68fb676a3b6589fce9aed79140bf37b667:scripts/README.md').stdout
section = run('show', 'e3a2d2e662f2e606f318d35f4fccc63ba9738f7c:scripts/README.md').stdout
if prefix.count(anchor) != 1 or section.count(anchor) != 1:
    raise SystemExit('README anchor mismatch')
merged = prefix.split(anchor, 1)[0] + section[section.index(anchor):]
info = lo['scripts_readme']
if info.get('computed_git_blob') != info['expected_git_blob']:
    raise SystemExit('README computed/expected Git blob metadata mismatch')
if len(merged) != info['expected_bytes'] or merged.count(b'\n') != info['expected_lines']:
    raise SystemExit('README shape mismatch')
if hashlib.sha256(merged).hexdigest() != info['expected_sha256']:
    raise SystemExit('README raw SHA mismatch')
computed = run('hash-object', '--stdin', input_bytes=merged).stdout.decode().strip()
if computed != info['expected_git_blob']:
    raise SystemExit('README blob mismatch')
if run('cat-file', '-t', info['expected_git_blob'], check=False).returncode == 0:
    raise SystemExit('future README blob unexpectedly exists before replay')

if 'assert_clean_primary_storage_unshared' not in execution_driver['shell'] or 'st_nlink' not in execution_driver['shell']:
    raise SystemExit('clean-primary st_nlink hardlink proof is missing from the driver')
if 'status --porcelain=v1 --untracked-files=all --ignored=traditional --ignore-submodules=none' not in execution_driver['shell']:
    raise SystemExit('complete whole-worktree ignored/untracked cleanliness proof is missing')
# SOURCE is intentionally not required to be clean while this static
# validation runs; clean-primary is separately required to be completely clean before replay mutation.
if out('rev-parse', '--is-inside-work-tree') != 'true' or out('rev-parse', '--is-bare-repository') != 'false':
    raise SystemExit('repository shape mismatch')
PY
}

# Verify SOURCE read-only, build a dedicated clean-primary, then create replay.
assert_tools
bind_source_identity
assert_root_shape
assert_worktree_separation
static_validate_matrix "$SOURCE"
MATRIX_SOURCE_VALIDATED=1
bootstrap_clean_primary
static_validate_matrix "$CLEAN_PRIMARY"
assert_clean_primary_state
assert_worktree_separation

# Bootstrap a standalone detached replay repository without git worktree add or fetch.
# Replay reads/mutations use clean-primary and replay only; SOURCE is never a workspace.
create_replay_root
assert_replay_preinit_state
CLEANUP_ALLOWLIST=("$REPLAY" "$README_TMP" "$MATRIX_SNAPSHOT" "$REPLAY_ROOT")
CLEAN_PRIMARY_CLEANUP_ALLOWLIST=("$CLEAN_PRIMARY_ROOT")
before_mutation
bind_matrix_snapshot
before_mutation
assert_root_shape
before_mutation
git_hermetic init "$REPLAY" >/dev/null
assert_root_shape
assert_worktree_separation
REPLAY_GIT_DIR="$REPLAY/.git"
test -d "$REPLAY_GIT_DIR" || fail "replay Git directory was not created"
test "$(git_replay rev-parse --absolute-git-dir)" = "$REPLAY_GIT_DIR" || fail "replay Git directory escaped replay root"
assert_root_shape
assert_worktree_separation
before_mutation
$MKDIR -p "$REPLAY/.git/objects/info"
before_mutation
printf '%s\n' "$CLEAN_PRIMARY_OBJECTS" > "$REPLAY/.git/objects/info/alternates"
before_mutation
git_replay config --local core.hooksPath /dev/null
before_mutation
git_replay config --local protocol.allow never
before_mutation
git_replay update-ref refs/remotes/origin/dev "$BASE"
before_mutation
git_replay update-ref refs/remotes/origin/main "$MAIN"
before_mutation
git_replay update-ref --no-deref HEAD "$BASE"
BOOTSTRAP_HEAD="$BASE"
BOOTSTRAP_TREE="$BASE_TREE"
before_mutation
git_replay read-tree --reset -u "$BASE"
CURRENT_HEAD="$(git_replay rev-parse HEAD)"
CURRENT_TREE="$(git_replay rev-parse HEAD^{tree})"
test "$CURRENT_HEAD" = "$BASE" || fail 'initial detached HEAD is not BASE'
test "$CURRENT_TREE" = "$BASE_TREE" || fail 'initial base tree mismatch'
REPLAY_READY=1
BOOTSTRAP_HEAD=''
BOOTSTRAP_TREE=''
assert_replay_state "$CURRENT_HEAD" "$CURRENT_TREE"
assert_replay_closure
REPLAY_GIT_BOUND=1
assert_root_shape
assert_worktree_separation
before_mutation

# Ordered execution. Ranges use exact inclusive source order. Semantic lanes and matrix
# stages project only approved paths; no candidate-to-source whole-tree diff/apply occurs.
apply_range_lane renderer-lifecycle
apply_semantic_lane renderer-lifecycle
apply_range_lane static-manifest-chain
apply_range_lane authentication-design-token-manifest
apply_semantic_lane authentication-semantic-delta
apply_range_lane fixture-registry-authority
apply_semantic_lane fixture-registry-authority
apply_range_lane apple-benchmark-range
apply_range_lane proxy-deployment-proof
apply_matrix_stage launcher
assert_stage_two_overlap
apply_semantic_lane dependency-audit-correction
apply_semantic_lane swift-parity-correction
apply_matrix_stage live
merge_scripts_readme

before_mutation
assert_final_matrix
assert_forbidden_ancestry
assert_primary_pins
printf 'FINAL_HEAD=%s\nREMOTE_DEV=%s\nINDEPENDENT_APPROVAL_REQUIRED=1\nNO_PUSH_PERFORMED=1\n' "$CURRENT_HEAD" "$(git_primary rev-parse origin/dev)"
assert_replay_closure
cleanup_success_only "$REPLAY" "$README_TMP" "$MATRIX_SNAPSHOT"
# Keep the post-call lifecycle ledger explicit: cleanup_success_only resets this only after the replay child was removed.
REPLAY_GIT_BOUND=0
cleanup_clean_primary_success_only
printf 'TASK409_FINAL_REPLAY_OK=1\nCLEAN_PRIMARY_REMOVED=1\n'
```


## Projection and range state bindings

Every content projection declares a source-parent tree plus exact per-path blob, mode, and type/absence records. It also declares the replay-stage precondition tree for each owned path; launcher uses the proxy candidate tree, while live uses the d3 tree only for the three mechanical overlaps and the proxy tree for live-only paths. The driver verifies those records before the projection and again for the path immediately before each CAS update. Every range source commit carries exact target blob, mode, and type/absence postconditions that are checked after cherry-pick and before commit. Ancestry-audit cumulative patch IDs are recomputed from their declared left/right ranges and path allowlists.

## No-live boundary and limitations

No live prompt, login, WebSocket, screenshot, deployment, proxy call, identity-provider call, credential use, or Hermes process is authorized by this artifact. Those actions require a completed replay, exact marker and watermark gates, and separate approval.

The expected merged README blob was computed from local source objects but is not stored locally. No replay, commit, push, or live proof was run, so this artifact makes no claim that a future integration checkout passes the fanout.

## Validation contract

| Check | Expected |
|---|---:|
| Launcher paths | `11` |
| Live-proof paths | `22` |
| Union paths | `29` |
| Intersection paths | `4` |
| Non-README launcher mechanical paths | `10` |
| Non-README live mechanical paths | `21` |
| Stage-two d3 overlap paths | `3` |
| JSON companion | `/tmp/hermternal-397-integrate/handover/issue-397/task464-candidate5-linux-v1-final/candidate-five.json` |
| Driver schema | `hermternal.task409.execution-driver.v1` |
| Driver shell SHA-256 | `9995382f83d26bb22a8c7641c1dc2f5a7157b7530f9eaadd0b73e329ecf2e75f` |
| Ordered driver steps | `21` |
| Declared projection state maps | `7` |
| Range target postcondition paths | `242` |
| Environment contract | exact `/usr/bin/env -i` allowlist; reject numbered Git config and Python/runtime overrides |
| Swift source SHA | `221620c04bb051f2597c52bdeb16ccc55c5b2e9c` |
| Shell body bytes | `289319` |
| Shell body lines | `5977` |
| Target-state mirror entries | `71` |
| Target-state mirror paths | `242` |
| Historical changed-path mirror entries | `123` |
| Historical changed-path mirror paths | `532` |

## Machine-readable parity appendix

This appendix mirrors every JSON object carrying `target_states` and `changed_paths`, including historical compatibility objects and ordered lane ledgers. The validator requires exact structural equality, target-state hash/mode/type content, and entry/path counts.

```json
{
  "historical_changed_paths": [
    {
      "changed_paths": [
        "apps/web/src/lib/terminal/README.md",
        "apps/web/src/lib/terminal/renderer.test.ts",
        "apps/web/tests/bench/terminal-renderer.provenance.ts"
      ],
      "json_pointer": "/ordered_lanes/0/range/source_commits/0"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/terminal/README.md",
        "apps/web/src/lib/terminal/renderer.test.ts",
        "apps/web/tests/bench/terminal-renderer.bench.ts",
        "apps/web/tests/bench/terminal-renderer.provenance.ts"
      ],
      "json_pointer": "/ordered_lanes/0/range/source_commits/1"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/terminal/README.md",
        "apps/web/src/lib/terminal/renderer.test.ts",
        "apps/web/tests/bench/terminal-renderer.bench.ts",
        "apps/web/tests/bench/terminal-renderer.provenance.ts"
      ],
      "json_pointer": "/ordered_lanes/0/range/source_commits/2"
    },
    {
      "changed_paths": [
        "apps/web/README.md",
        "apps/web/package.json",
        "apps/web/tests/static/assert-static-build.mjs",
        "apps/web/tests/static/terminal-only-manifest.mjs",
        "apps/web/tests/static/terminal-only-manifest.test.mjs"
      ],
      "json_pointer": "/ordered_lanes/1/range/source_commits/0"
    },
    {
      "changed_paths": [
        "apps/web/tests/static/terminal-only-manifest.mjs",
        "apps/web/tests/static/terminal-only-manifest.test.mjs"
      ],
      "json_pointer": "/ordered_lanes/1/range/source_commits/1"
    },
    {
      "changed_paths": [
        "apps/web/README.md",
        "apps/web/tests/static/terminal-only-manifest.mjs",
        "apps/web/tests/static/terminal-only-manifest.test.mjs"
      ],
      "json_pointer": "/ordered_lanes/1/range/source_commits/2"
    },
    {
      "changed_paths": [
        "contracts/design-tokens/README.md",
        "contracts/design-tokens/web/README.md",
        "contracts/design-tokens/web/artboards.json",
        "contracts/design-tokens/web/test_validate.py",
        "contracts/design-tokens/web/validate.py"
      ],
      "json_pointer": "/ordered_lanes/2/range/source_commits/0"
    },
    {
      "changed_paths": [
        "contracts/design-tokens/README.md",
        "contracts/design-tokens/web/README.md",
        "contracts/design-tokens/web/artboards.json",
        "contracts/design-tokens/web/validate.py"
      ],
      "json_pointer": "/ordered_lanes/2/range/source_commits/1"
    },
    {
      "changed_paths": [
        "contracts/design-tokens/web/test_validate.py"
      ],
      "json_pointer": "/ordered_lanes/2/range/source_commits/2"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/auth-ui/AuthPreview.svelte",
        "apps/web/src/lib/auth-ui/AuthPreview.test.ts",
        "apps/web/src/lib/auth-ui/BrowserAuthView.svelte",
        "apps/web/src/lib/auth-ui/BrowserAuthView.test.ts",
        "apps/web/src/lib/auth-ui/ProviderCard.svelte",
        "apps/web/src/lib/auth-ui/ProviderCard.test.ts",
        "apps/web/src/lib/auth-ui/browser-auth-session.test.ts",
        "apps/web/src/lib/auth-ui/browser-auth.md",
        "apps/web/src/lib/auth-ui/fixtures.ts",
        "apps/web/src/lib/auth-ui/types.ts",
        "apps/web/src/lib/root-route.test.ts",
        "apps/web/src/lib/root-route.ts",
        "apps/web/src/lib/workspace/Composer.svelte",
        "apps/web/src/lib/workspace/Composer.test.ts",
        "apps/web/src/lib/workspace/LiveWorkspaceView.svelte",
        "apps/web/src/lib/workspace/LiveWorkspaceView.test.ts",
        "apps/web/src/lib/workspace/WorkspacePreview.svelte",
        "apps/web/src/lib/workspace/WorkspacePreview.test.ts",
        "apps/web/src/lib/workspace/live-workspace-session.test.ts",
        "apps/web/src/lib/workspace/live-workspace-session.ts",
        "apps/web/src/routes/ui-preview/+page.svelte",
        "apps/web/src/routes/ui-preview/ui-preview.test.ts",
        "apps/web/tests/e2e/ui-preview.spec.ts"
      ],
      "json_pointer": "/ordered_lanes/3/rehearsal_oracle"
    },
    {
      "changed_paths": [
        "contracts/fixtures/index.json",
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py",
        "contracts/fixtures/validator/validation-baseline.json"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/0"
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py",
        "contracts/fixtures/validator/validation-baseline.json"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/1"
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/2"
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/3"
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/4"
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/5"
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/6"
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/7"
    },
    {
      "changed_paths": [
        "scripts/fixture_registry_authority.v2.hardened.json"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/8"
    },
    {
      "changed_paths": [
        "contracts/fixtures/README.md",
        "docs/architecture/fixture-registry-authority.md",
        "scripts/fixture_authority_test_source.py",
        "scripts/fixture_registry_authority.objects.bundle",
        "scripts/fixture_registry_authority.v2.hardened.pin.json",
        "scripts/test_fixture_registry_authority.py",
        "scripts/verify_fixture_registry_authority.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/9"
    },
    {
      "changed_paths": [
        "benchmarks/apple/.gitignore",
        "benchmarks/apple/Package.swift",
        "benchmarks/apple/README.md",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/MockWorkloads.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Models.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Resources/workload.json",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Sources/apple-benchmark/main.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/0"
    },
    {
      "changed_paths": [
        "benchmarks/apple/README.md",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/1"
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/2"
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/3"
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Sources/apple-benchmark/main.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/4"
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/5"
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/6"
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Models.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/7"
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/MockWorkloads.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Models.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Sources/apple-benchmark/main.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/8"
    },
    {
      "changed_paths": [
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/9"
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/10"
    },
    {
      "changed_paths": [
        "benchmarks/apple/README.md"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/11"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/0"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/1"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/2"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/3"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/4"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/5"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/6"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/7"
    },
    {
      "changed_paths": [
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/8"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/9"
    },
    {
      "changed_paths": [
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/10"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/11"
    },
    {
      "changed_paths": [
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/12"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/13"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/14"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/15"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/16"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/17"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/18"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/19"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/20"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/21"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/22"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/23"
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/24"
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/25"
    },
    {
      "changed_paths": [
        "docs/deployment/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/26"
    },
    {
      "changed_paths": [
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/27"
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/28"
    },
    {
      "changed_paths": [
        "scripts/test_caddy_proof.py"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/29"
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/30"
    },
    {
      "changed_paths": [
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/31"
    },
    {
      "changed_paths": [
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/32"
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/33"
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/34"
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/35"
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/36"
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/37"
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/38"
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/39"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_commit"
    },
    {
      "changed_paths": [
        "scripts/live_run_marker.py",
        "scripts/test_live_run_marker.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/0"
    },
    {
      "changed_paths": [
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/1"
    },
    {
      "changed_paths": [
        "apps/web/tests/live/README.md",
        "scripts/README.md",
        "scripts/read_launcher_result.py",
        "scripts/test_read_launcher_result.py",
        "scripts/test_with_live_credential.py",
        "scripts/with_live_credential.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/2"
    },
    {
      "changed_paths": [
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/3"
    },
    {
      "changed_paths": [
        "scripts/live_run_marker.py",
        "scripts/test_live_run_marker.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/4"
    },
    {
      "changed_paths": [
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/5"
    },
    {
      "changed_paths": [
        "apps/web/tests/live/README.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/live_run_marker.py",
        "scripts/test_hermes_agent.py",
        "scripts/test_live_run_marker.py",
        "scripts/test_with_live_credential.py",
        "scripts/with_live_credential.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/6"
    },
    {
      "changed_paths": [
        "apps/web/tests/live/README.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/live_run_marker.py",
        "scripts/read_launcher_result.py",
        "scripts/test_hermes_agent.py",
        "scripts/test_live_run_marker.py",
        "scripts/test_read_launcher_result.py",
        "scripts/test_with_live_credential.py",
        "scripts/with_live_credential.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/7"
    },
    {
      "changed_paths": [
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/live_run_marker.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/8"
    },
    {
      "changed_paths": [
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/live_run_marker.py",
        "scripts/read_launcher_result.py",
        "scripts/test_hermes_agent.py",
        "scripts/test_live_run_marker.py",
        "scripts/test_read_launcher_result.py",
        "scripts/test_with_live_credential.py",
        "scripts/with_live_credential.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/9"
    },
    {
      "changed_paths": [
        "scripts/README.md",
        "scripts/live_run_marker.py",
        "scripts/read_launcher_result.py",
        "scripts/test_live_run_marker.py",
        "scripts/test_read_launcher_result.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/10"
    },
    {
      "changed_paths": [
        "scripts/README.md",
        "scripts/read_launcher_result.py",
        "scripts/test_read_launcher_result.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/11"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "apps/web/tests/live/README.md",
        "scripts/test_with_live_credential.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/12"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "apps/web/tests/live/README.md",
        "scripts/README.md",
        "scripts/test_read_launcher_result.py",
        "scripts/test_with_live_credential.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/13"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py",
        "scripts/test_with_live_credential.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/14"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/15"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/16"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/17"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/live_run_marker.py",
        "scripts/test_hermes_agent.py",
        "scripts/test_live_run_marker.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/18"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/19"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/20"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/live_run_marker.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/21"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/22"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/23"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/7/source_ancestry_audit/source_commits/24"
    },
    {
      "changed_paths": [
        "docs/security/dependency-audit.md",
        "scripts/dependency_audit.py",
        "scripts/test_dependency_audit.py"
      ],
      "json_pointer": "/ordered_lanes/8/source_commit"
    },
    {
      "changed_paths": [
        "contracts/swift-parity/README.md",
        "contracts/swift-parity/Sources/HermternalSwiftParity/Parity.swift",
        "contracts/swift-parity/Tests/HermternalSwiftParityTests/ParityTests.swift"
      ],
      "json_pointer": "/ordered_lanes/9/source_commit"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/live-screenshot-capture.mjs"
      ],
      "json_pointer": "/ordered_lanes/10/source_commit"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/live-screenshot-capture.mjs"
      ],
      "json_pointer": "/ordered_lanes/10/intermediate_checkpoint"
    },
    {
      "changed_paths": [
        ".agents/skills/deploy-hermes-agent/SKILL.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/0"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/README.md"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/1"
    },
    {
      "changed_paths": [
        "apps/web/playwright.live.config.ts",
        "apps/web/src/lib/live-artifact-policy.test.ts",
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/live-playwright-config.mjs",
        "apps/web/tests/live/live-proof-ledger.mjs",
        "apps/web/tests/live/live-proof-page-bridge.mjs",
        "apps/web/tests/live/live-proof-parent-compat.mjs",
        "apps/web/tests/live/live-proof-status.mjs",
        "apps/web/tests/live/live-reconciliation-auth.mjs",
        "apps/web/tests/live/live-reconciliation-transport.mjs",
        "apps/web/tests/live/live-reconciliation.mjs",
        "apps/web/tests/live/live-screenshot-capture.mjs",
        "apps/web/tests/live/live-support-parent-compat.mjs",
        "apps/web/tests/live/official-hermes.spec.ts",
        "apps/web/tests/live/reconcile-live-proof.spec.ts"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/2"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-artifact-policy.test.ts",
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/README.md",
        "apps/web/tests/live/live-artifact-policy.mjs",
        "apps/web/tests/live/live-reconciliation-transport.mjs",
        "apps/web/tests/live/live-reconciliation.mjs",
        "apps/web/tests/live/official-hermes.spec.ts",
        "scripts/README.md",
        "scripts/test_with_live_credential.py",
        "scripts/with_live_credential.py"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/3"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/README.md",
        "apps/web/tests/live/live-proof-parent-compat.mjs",
        "apps/web/tests/live/live-screenshot-capture.mjs",
        "apps/web/tests/live/live-screenshot-contract.mjs",
        "apps/web/tests/live/live-support-parent-compat.mjs",
        "apps/web/tests/live/live-trusted-executables.mjs",
        "apps/web/tests/live/official-hermes.spec.ts",
        "scripts/README.md",
        "scripts/test_with_live_credential.py",
        "scripts/with_live_credential.py"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/4"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-artifact-policy.test.ts",
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/README.md",
        "apps/web/tests/live/live-proof-parent-compat.mjs",
        "apps/web/tests/live/live-screenshot-capture.mjs",
        "apps/web/tests/live/live-screenshot-contract.mjs",
        "apps/web/tests/live/live-trusted-executables.mjs",
        "scripts/with_live_credential.py"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/5"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/README.md",
        "apps/web/tests/live/live-screenshot-capture.mjs",
        "apps/web/tests/live/live-trusted-executables.mjs"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/6"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/README.md",
        "apps/web/tests/live/live-screenshot-capture.mjs",
        "apps/web/tests/live/live-trusted-executables.mjs"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/7"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/README.md",
        "apps/web/tests/live/live-screenshot-capture.mjs",
        "apps/web/tests/live/live-trusted-executables.mjs"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/8"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/README.md",
        "apps/web/tests/live/live-screenshot-capture.mjs"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/9"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/live-screenshot-capture.mjs"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/10"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-screenshot-contract.test.ts",
        "apps/web/tests/live/live-screenshot-capture.mjs"
      ],
      "json_pointer": "/ordered_lanes/10/source_ancestry_audit/source_commits/11"
    },
    {
      "changed_paths": [
        "apps/web/tests/live/README.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/live_run_marker.py",
        "scripts/test_hermes_agent.py",
        "scripts/test_live_run_marker.py",
        "scripts/test_with_live_credential.py",
        "scripts/with_live_credential.py"
      ],
      "json_pointer": "/historical_compatibility_objects/0"
    },
    {
      "changed_paths": [
        "apps/web/tests/live/README.md",
        "scripts/README.md",
        "scripts/hermes_agent.py",
        "scripts/live_run_marker.py",
        "scripts/read_launcher_result.py",
        "scripts/test_hermes_agent.py",
        "scripts/test_live_run_marker.py",
        "scripts/test_read_launcher_result.py",
        "scripts/test_with_live_credential.py",
        "scripts/with_live_credential.py"
      ],
      "json_pointer": "/historical_compatibility_objects/1"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-artifact-policy.test.ts",
        "apps/web/src/lib/live-proof-ledger.test.ts",
        "apps/web/src/lib/live-reconciliation-selection.test.ts",
        "apps/web/src/lib/live-screenshot-capture.test.ts",
        "apps/web/tests/live/README.md",
        "apps/web/tests/live/live-proof-ledger.mjs",
        "apps/web/tests/live/live-proof-page-bridge.mjs",
        "apps/web/tests/live/live-proof-parent-compat.mjs",
        "apps/web/tests/live/official-hermes.spec.ts"
      ],
      "json_pointer": "/historical_compatibility_objects/2"
    },
    {
      "changed_paths": [
        "apps/web/playwright.live.config.ts",
        "apps/web/src/lib/live-screenshot-capture.test.ts",
        "apps/web/tests/live/README.md",
        "apps/web/tests/live/live-playwright-config.mjs",
        "apps/web/tests/live/live-proof-status.mjs",
        "apps/web/tests/live/live-reconciliation-auth.mjs",
        "apps/web/tests/live/live-reconciliation-transport.mjs",
        "apps/web/tests/live/live-reconciliation.mjs",
        "apps/web/tests/live/live-screenshot-capture.mjs",
        "apps/web/tests/live/live-support-parent-compat.mjs",
        "apps/web/tests/live/official-hermes.spec.ts",
        "apps/web/tests/live/reconcile-live-proof.spec.ts"
      ],
      "json_pointer": "/historical_compatibility_objects/3"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/live-screenshot-capture.test.ts",
        "apps/web/tests/live/README.md",
        "apps/web/tests/live/live-playwright-config.mjs",
        "apps/web/tests/live/live-screenshot-capture.mjs",
        "docs/security/redaction-audit.md"
      ],
      "json_pointer": "/historical_compatibility_objects/4"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/auth-ui/AuthPreview.svelte",
        "apps/web/src/lib/auth-ui/AuthPreview.test.ts",
        "apps/web/src/lib/auth-ui/BrowserAuthView.svelte",
        "apps/web/src/lib/auth-ui/BrowserAuthView.test.ts",
        "apps/web/src/lib/auth-ui/ProviderCard.svelte",
        "apps/web/src/lib/auth-ui/ProviderCard.test.ts",
        "apps/web/src/lib/auth-ui/browser-auth-session.test.ts",
        "apps/web/src/lib/auth-ui/browser-auth.md",
        "apps/web/src/lib/auth-ui/fixtures.ts",
        "apps/web/src/lib/auth-ui/types.ts",
        "apps/web/src/lib/root-route.test.ts",
        "apps/web/src/lib/root-route.ts",
        "apps/web/src/lib/workspace/Composer.svelte",
        "apps/web/src/lib/workspace/Composer.test.ts",
        "apps/web/src/lib/workspace/LiveWorkspaceView.svelte",
        "apps/web/src/lib/workspace/LiveWorkspaceView.test.ts",
        "apps/web/src/lib/workspace/WorkspacePreview.svelte",
        "apps/web/src/lib/workspace/WorkspacePreview.test.ts",
        "apps/web/src/lib/workspace/live-workspace-session.test.ts",
        "apps/web/src/lib/workspace/live-workspace-session.ts",
        "apps/web/src/routes/ui-preview/+page.svelte",
        "apps/web/src/routes/ui-preview/ui-preview.test.ts",
        "apps/web/tests/e2e/ui-preview.spec.ts"
      ],
      "json_pointer": "/historical_compatibility_objects/5"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/auth-ui/AuthPreview.svelte",
        "apps/web/src/lib/auth-ui/AuthPreview.test.ts"
      ],
      "json_pointer": "/historical_compatibility_objects/6"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/terminal/README.md",
        "apps/web/src/lib/terminal/renderer.test.ts"
      ],
      "json_pointer": "/historical_compatibility_objects/7"
    },
    {
      "changed_paths": [
        "apps/web/src/lib/terminal/renderer.test.ts"
      ],
      "json_pointer": "/historical_compatibility_objects/8"
    }
  ],
  "target_states": [
    {
      "changed_paths": [
        "apps/web/src/lib/terminal/README.md",
        "apps/web/src/lib/terminal/renderer.test.ts",
        "apps/web/tests/bench/terminal-renderer.provenance.ts"
      ],
      "json_pointer": "/ordered_lanes/0/range/source_commits/0",
      "target_states": {
        "apps/web/src/lib/terminal/README.md": {
          "blob": "9a14f7add8200e90fadee740a27647ea4de4e0fe",
          "mode": "100644",
          "tree": "b0df525168205e2433c3e1ab94b94ccdbac9beb8",
          "type": "file"
        },
        "apps/web/src/lib/terminal/renderer.test.ts": {
          "blob": "0aac7f24615dfa408911b2ae290b4240fdab510e",
          "mode": "100644",
          "tree": "b0df525168205e2433c3e1ab94b94ccdbac9beb8",
          "type": "file"
        },
        "apps/web/tests/bench/terminal-renderer.provenance.ts": {
          "blob": "007fd26b93b0bd3134da10ee24a8b923a786ae97",
          "mode": "100644",
          "tree": "b0df525168205e2433c3e1ab94b94ccdbac9beb8",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "apps/web/src/lib/terminal/README.md",
        "apps/web/src/lib/terminal/renderer.test.ts",
        "apps/web/tests/bench/terminal-renderer.bench.ts",
        "apps/web/tests/bench/terminal-renderer.provenance.ts"
      ],
      "json_pointer": "/ordered_lanes/0/range/source_commits/1",
      "target_states": {
        "apps/web/src/lib/terminal/README.md": {
          "blob": "e4f9814aa3ec4d7dbecd9fed4c680a9963ab4a88",
          "mode": "100644",
          "tree": "3abc812e25d701b381dae04ea9e4e2c8cb54985f",
          "type": "file"
        },
        "apps/web/src/lib/terminal/renderer.test.ts": {
          "blob": "6ee5d617805b4b3fe0921c4af8ca1b21246a4e4f",
          "mode": "100644",
          "tree": "3abc812e25d701b381dae04ea9e4e2c8cb54985f",
          "type": "file"
        },
        "apps/web/tests/bench/terminal-renderer.bench.ts": {
          "blob": "2037ffa1233fc6f7263abce5c60deede1e12967b",
          "mode": "100644",
          "tree": "3abc812e25d701b381dae04ea9e4e2c8cb54985f",
          "type": "file"
        },
        "apps/web/tests/bench/terminal-renderer.provenance.ts": {
          "blob": "004e1ff679f7f487ffeaeac367d3e30fd6711807",
          "mode": "100644",
          "tree": "3abc812e25d701b381dae04ea9e4e2c8cb54985f",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "apps/web/src/lib/terminal/README.md",
        "apps/web/src/lib/terminal/renderer.test.ts",
        "apps/web/tests/bench/terminal-renderer.bench.ts",
        "apps/web/tests/bench/terminal-renderer.provenance.ts"
      ],
      "json_pointer": "/ordered_lanes/0/range/source_commits/2",
      "target_states": {
        "apps/web/src/lib/terminal/README.md": {
          "blob": "8690ed844473cf8db70a7953a8dce3ea746a3da7",
          "mode": "100644",
          "tree": "8122900638aa0a1fcad57653328ade07631f4f75",
          "type": "file"
        },
        "apps/web/src/lib/terminal/renderer.test.ts": {
          "blob": "6448ddf3286a1e3d04dbeeab6dfe18e60d3da14d",
          "mode": "100644",
          "tree": "8122900638aa0a1fcad57653328ade07631f4f75",
          "type": "file"
        },
        "apps/web/tests/bench/terminal-renderer.bench.ts": {
          "blob": "a55bec987d304fe2dc243ffc83adfe1a9e602f2b",
          "mode": "100644",
          "tree": "8122900638aa0a1fcad57653328ade07631f4f75",
          "type": "file"
        },
        "apps/web/tests/bench/terminal-renderer.provenance.ts": {
          "blob": "98ff1911d1ea9406bc0de0fb25f7a49b7e6de170",
          "mode": "100644",
          "tree": "8122900638aa0a1fcad57653328ade07631f4f75",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "apps/web/README.md",
        "apps/web/package.json",
        "apps/web/tests/static/assert-static-build.mjs",
        "apps/web/tests/static/terminal-only-manifest.mjs",
        "apps/web/tests/static/terminal-only-manifest.test.mjs"
      ],
      "json_pointer": "/ordered_lanes/1/range/source_commits/0",
      "target_states": {
        "apps/web/README.md": {
          "blob": "c2aab6c25023d4f3ed8ba3ba8980df5c95f13684",
          "mode": "100644",
          "tree": "39975d2e03c13762e906ab9eb760f422d70a3147",
          "type": "file"
        },
        "apps/web/package.json": {
          "blob": "50ac7bb957b896b7247c054ada6a753d5ca16734",
          "mode": "100644",
          "tree": "39975d2e03c13762e906ab9eb760f422d70a3147",
          "type": "file"
        },
        "apps/web/tests/static/assert-static-build.mjs": {
          "blob": "7e25d63cc59919fc253457255df613947041ba6d",
          "mode": "100644",
          "tree": "39975d2e03c13762e906ab9eb760f422d70a3147",
          "type": "file"
        },
        "apps/web/tests/static/terminal-only-manifest.mjs": {
          "blob": "bc56ed3d4b92d5992e335bf8920f86e9070d8070",
          "mode": "100644",
          "tree": "39975d2e03c13762e906ab9eb760f422d70a3147",
          "type": "file"
        },
        "apps/web/tests/static/terminal-only-manifest.test.mjs": {
          "blob": "f680ebb3df72b48876324e218900aa57d2600fd9",
          "mode": "100644",
          "tree": "39975d2e03c13762e906ab9eb760f422d70a3147",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "apps/web/tests/static/terminal-only-manifest.mjs",
        "apps/web/tests/static/terminal-only-manifest.test.mjs"
      ],
      "json_pointer": "/ordered_lanes/1/range/source_commits/1",
      "target_states": {
        "apps/web/tests/static/terminal-only-manifest.mjs": {
          "blob": "4dd06e4c053c5e186f72a08335f29e5599f7a0b2",
          "mode": "100644",
          "tree": "f2db122ea16638ca4234d658fc38fef3d083031f",
          "type": "file"
        },
        "apps/web/tests/static/terminal-only-manifest.test.mjs": {
          "blob": "40580cd2ac2c1de285a70fedacf730844ba26f25",
          "mode": "100644",
          "tree": "f2db122ea16638ca4234d658fc38fef3d083031f",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "apps/web/README.md",
        "apps/web/tests/static/terminal-only-manifest.mjs",
        "apps/web/tests/static/terminal-only-manifest.test.mjs"
      ],
      "json_pointer": "/ordered_lanes/1/range/source_commits/2",
      "target_states": {
        "apps/web/README.md": {
          "blob": "c4a5b9d04cca41b7195dec1f1e79fc5e23bba054",
          "mode": "100644",
          "tree": "14ca3391fb16f5020ef3161c4d50d75be98bc1bc",
          "type": "file"
        },
        "apps/web/tests/static/terminal-only-manifest.mjs": {
          "blob": "e92df8a7e2eb0461f58b6d5a5f4b9e57bcc8d041",
          "mode": "100644",
          "tree": "14ca3391fb16f5020ef3161c4d50d75be98bc1bc",
          "type": "file"
        },
        "apps/web/tests/static/terminal-only-manifest.test.mjs": {
          "blob": "99784c0772234fa9ae02c1b3fdffd682500e7ac9",
          "mode": "100644",
          "tree": "14ca3391fb16f5020ef3161c4d50d75be98bc1bc",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/design-tokens/README.md",
        "contracts/design-tokens/web/README.md",
        "contracts/design-tokens/web/artboards.json",
        "contracts/design-tokens/web/test_validate.py",
        "contracts/design-tokens/web/validate.py"
      ],
      "json_pointer": "/ordered_lanes/2/range/source_commits/0",
      "target_states": {
        "contracts/design-tokens/README.md": {
          "blob": "55757735438068358207008491a55dceae9a4dfe",
          "mode": "100644",
          "tree": "0b99f2743fd401cd18cc48355f9d3852d0847e06",
          "type": "file"
        },
        "contracts/design-tokens/web/README.md": {
          "blob": "bb1cf3745ad4ebbfb35acd07cd75b45c409f9501",
          "mode": "100644",
          "tree": "0b99f2743fd401cd18cc48355f9d3852d0847e06",
          "type": "file"
        },
        "contracts/design-tokens/web/artboards.json": {
          "blob": "1a617dfc7a944dd3074fc20521dc65a00c6b5df2",
          "mode": "100644",
          "tree": "0b99f2743fd401cd18cc48355f9d3852d0847e06",
          "type": "file"
        },
        "contracts/design-tokens/web/test_validate.py": {
          "blob": "69b09d90b537aa1ad4e859f5fb9805576f6e0ad2",
          "mode": "100644",
          "tree": "0b99f2743fd401cd18cc48355f9d3852d0847e06",
          "type": "file"
        },
        "contracts/design-tokens/web/validate.py": {
          "blob": "e97fe4babf2d71a7149c23317d169547e4affce3",
          "mode": "100644",
          "tree": "0b99f2743fd401cd18cc48355f9d3852d0847e06",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/design-tokens/README.md",
        "contracts/design-tokens/web/README.md",
        "contracts/design-tokens/web/artboards.json",
        "contracts/design-tokens/web/validate.py"
      ],
      "json_pointer": "/ordered_lanes/2/range/source_commits/1",
      "target_states": {
        "contracts/design-tokens/README.md": {
          "blob": "88b860dadb4d513ac55617bfc746089d43a70211",
          "mode": "100644",
          "tree": "cac1d57e79f601aa3f184506a8b35252d0883030",
          "type": "file"
        },
        "contracts/design-tokens/web/README.md": {
          "blob": "2c946031b0644104cb1f03ad5dc0df62a47e1260",
          "mode": "100644",
          "tree": "cac1d57e79f601aa3f184506a8b35252d0883030",
          "type": "file"
        },
        "contracts/design-tokens/web/artboards.json": {
          "blob": "addff41c1016fde7dbf670feb5408a4d2aa71f86",
          "mode": "100644",
          "tree": "cac1d57e79f601aa3f184506a8b35252d0883030",
          "type": "file"
        },
        "contracts/design-tokens/web/validate.py": {
          "blob": "109cdb70d051253a79744608e3d0143a14e34af7",
          "mode": "100644",
          "tree": "cac1d57e79f601aa3f184506a8b35252d0883030",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/design-tokens/web/test_validate.py"
      ],
      "json_pointer": "/ordered_lanes/2/range/source_commits/2",
      "target_states": {
        "contracts/design-tokens/web/test_validate.py": {
          "blob": "3dddf6b5f5aefdbd809c1a9e54efe8f72a93278e",
          "mode": "100644",
          "tree": "a11efeae95cbb0da0c08974786db287a1d150eb4",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/fixtures/index.json",
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py",
        "contracts/fixtures/validator/validation-baseline.json"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/0",
      "target_states": {
        "contracts/fixtures/index.json": {
          "blob": "b483e192b18b0df618547aeabbb8815de631e929",
          "mode": "100644",
          "tree": "878c8590ba55be3c67347a8f8e12808e04e2dec2",
          "type": "file"
        },
        "contracts/fixtures/validator/test_validate.py": {
          "blob": "724fe27ce74d0b613b1c6e87d3a75267d9da2c36",
          "mode": "100644",
          "tree": "878c8590ba55be3c67347a8f8e12808e04e2dec2",
          "type": "file"
        },
        "contracts/fixtures/validator/validate.py": {
          "blob": "3b4c0c1c50e8242829a3591cfe1d679451ca6425",
          "mode": "100644",
          "tree": "878c8590ba55be3c67347a8f8e12808e04e2dec2",
          "type": "file"
        },
        "contracts/fixtures/validator/validation-baseline.json": {
          "blob": "f919e41f29ffe5ca861e076d1c74d81820535a6e",
          "mode": "100644",
          "tree": "878c8590ba55be3c67347a8f8e12808e04e2dec2",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py",
        "contracts/fixtures/validator/validation-baseline.json"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/1",
      "target_states": {
        "contracts/fixtures/validator/test_validate.py": {
          "blob": "c367bcd9ca5f6858b65d1740464de125e2d5b721",
          "mode": "100644",
          "tree": "3ad3b1e708001d338a36246d8fbe05a70b8815a4",
          "type": "file"
        },
        "contracts/fixtures/validator/validate.py": {
          "blob": "3c960cd38e32a0d8d6e625ff63cb4543451d5ee2",
          "mode": "100644",
          "tree": "3ad3b1e708001d338a36246d8fbe05a70b8815a4",
          "type": "file"
        },
        "contracts/fixtures/validator/validation-baseline.json": {
          "blob": "743dd390f583b73b081e7fc0daffde07cb33980a",
          "mode": "100644",
          "tree": "3ad3b1e708001d338a36246d8fbe05a70b8815a4",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/2",
      "target_states": {
        "contracts/fixtures/validator/test_validate.py": {
          "blob": "80d0eea7964ec6cd1d8a39d29e88538e90610f59",
          "mode": "100644",
          "tree": "d1fdebe885f6fbc9e47522102f9287734ad31d07",
          "type": "file"
        },
        "contracts/fixtures/validator/validate.py": {
          "blob": "892f2261a7dc175fd2a49a8a13456e9085d71cfc",
          "mode": "100644",
          "tree": "d1fdebe885f6fbc9e47522102f9287734ad31d07",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/3",
      "target_states": {
        "contracts/fixtures/validator/test_validate.py": {
          "blob": "ede770e6b658f0cb05e551250da31c0167eebfd7",
          "mode": "100644",
          "tree": "fe1c54e65c103d279ccd8459dcef17c4bdca5d94",
          "type": "file"
        },
        "contracts/fixtures/validator/validate.py": {
          "blob": "2604980f36278eea8ef2303e676b2987fbcf33c8",
          "mode": "100644",
          "tree": "fe1c54e65c103d279ccd8459dcef17c4bdca5d94",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/4",
      "target_states": {
        "contracts/fixtures/validator/test_validate.py": {
          "blob": "9a76f281bb75bbcd7d55173583ce5ee6d88f8ffc",
          "mode": "100644",
          "tree": "4a5e9e9af382219e709f24173c2f299317089058",
          "type": "file"
        },
        "contracts/fixtures/validator/validate.py": {
          "blob": "8e4df88beaf07abec5fbd107fe0127513bedf84f",
          "mode": "100644",
          "tree": "4a5e9e9af382219e709f24173c2f299317089058",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/5",
      "target_states": {
        "contracts/fixtures/validator/test_validate.py": {
          "blob": "cdf446da5cda8c6ceaba11207d3ffe0eb300aa22",
          "mode": "100644",
          "tree": "0ec820649f2338e628a271c1434b34ec5a8d3121",
          "type": "file"
        },
        "contracts/fixtures/validator/validate.py": {
          "blob": "003194b17a9670b83a9f5a2f9f5cc0742d545361",
          "mode": "100644",
          "tree": "0ec820649f2338e628a271c1434b34ec5a8d3121",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/6",
      "target_states": {
        "contracts/fixtures/validator/test_validate.py": {
          "blob": "b226bf21b460bd5677546418ae87da3682e4d157",
          "mode": "100644",
          "tree": "9c606664821214be2b63501bdaa0d20c1f935683",
          "type": "file"
        },
        "contracts/fixtures/validator/validate.py": {
          "blob": "94dc23165670fbdf709eb56854817ec676f92f99",
          "mode": "100644",
          "tree": "9c606664821214be2b63501bdaa0d20c1f935683",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validate.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/7",
      "target_states": {
        "contracts/fixtures/validator/test_validate.py": {
          "blob": "aeb0cc8b9827e8c93fb45e65454bf38cff735a43",
          "mode": "100644",
          "tree": "93ad8df0080d9b988b443daa55b54ac0b34c06b1",
          "type": "file"
        },
        "contracts/fixtures/validator/validate.py": {
          "blob": "94441acf989acc8dbd4bd9053450653253ad5f96",
          "mode": "100644",
          "tree": "93ad8df0080d9b988b443daa55b54ac0b34c06b1",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/fixture_registry_authority.v2.hardened.json"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/8",
      "target_states": {
        "scripts/fixture_registry_authority.v2.hardened.json": {
          "blob": "40b26bf5f92cc41bad1286ca232937f240dba8eb",
          "mode": "100644",
          "tree": "c0531f5f2a8feb76a81530d77e1fbdc3733f3364",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "contracts/fixtures/README.md",
        "docs/architecture/fixture-registry-authority.md",
        "scripts/fixture_authority_test_source.py",
        "scripts/fixture_registry_authority.objects.bundle",
        "scripts/fixture_registry_authority.v2.hardened.pin.json",
        "scripts/test_fixture_registry_authority.py",
        "scripts/verify_fixture_registry_authority.py"
      ],
      "json_pointer": "/ordered_lanes/4/range/source_commits/9",
      "target_states": {
        "contracts/fixtures/README.md": {
          "blob": "54c3a3ed83271c43139377b22dcca23eac88e3b8",
          "mode": "100644",
          "tree": "eaf3def9a0a66f8d67c51f5122f78b194d400b99",
          "type": "file"
        },
        "docs/architecture/fixture-registry-authority.md": {
          "blob": "fbb4a100ec14eb354b784ad14cb97c9d7255a4f1",
          "mode": "100644",
          "tree": "eaf3def9a0a66f8d67c51f5122f78b194d400b99",
          "type": "file"
        },
        "scripts/fixture_authority_test_source.py": {
          "blob": "810efe41d1c8a5339966df97a6f3caa99e52eac6",
          "mode": "100644",
          "tree": "eaf3def9a0a66f8d67c51f5122f78b194d400b99",
          "type": "file"
        },
        "scripts/fixture_registry_authority.objects.bundle": {
          "blob": "12c6d69bb82efcecad0e2905003af814a8622917",
          "mode": "100644",
          "tree": "eaf3def9a0a66f8d67c51f5122f78b194d400b99",
          "type": "file"
        },
        "scripts/fixture_registry_authority.v2.hardened.pin.json": {
          "blob": "c5987548dbffb1b674ed2dd641bf05e3e18cc192",
          "mode": "100644",
          "tree": "eaf3def9a0a66f8d67c51f5122f78b194d400b99",
          "type": "file"
        },
        "scripts/test_fixture_registry_authority.py": {
          "blob": "613260e96d8adac4d4314e0c8be9df97ef3f9fcd",
          "mode": "100644",
          "tree": "eaf3def9a0a66f8d67c51f5122f78b194d400b99",
          "type": "file"
        },
        "scripts/verify_fixture_registry_authority.py": {
          "blob": "9cdb79994f6b6fbc31f50446caeb2731443c8b73",
          "mode": "100644",
          "tree": "eaf3def9a0a66f8d67c51f5122f78b194d400b99",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/.gitignore",
        "benchmarks/apple/Package.swift",
        "benchmarks/apple/README.md",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/MockWorkloads.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Models.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Resources/workload.json",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Sources/apple-benchmark/main.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/0",
      "target_states": {
        "benchmarks/apple/.gitignore": {
          "blob": "30bcfa4ed5ccf1f8ec2345e2662ac64067336180",
          "mode": "100644",
          "tree": "46ae7dfad21feead9f34690fbe25d2178488bef0",
          "type": "file"
        },
        "benchmarks/apple/Package.swift": {
          "blob": "29eb467036e5226b8e4733137926dd7fcaba1ee1",
          "mode": "100644",
          "tree": "46ae7dfad21feead9f34690fbe25d2178488bef0",
          "type": "file"
        },
        "benchmarks/apple/README.md": {
          "blob": "6a3c71e7fa3cf24947f7142cd7fbff2e4b6f6e4a",
          "mode": "100644",
          "tree": "46ae7dfad21feead9f34690fbe25d2178488bef0",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/MockWorkloads.swift": {
          "blob": "5a163135d4deb8c49db49893865bab7ba9747455",
          "mode": "100644",
          "tree": "46ae7dfad21feead9f34690fbe25d2178488bef0",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Models.swift": {
          "blob": "7d9e7146d6e1adb13e54dd26e7e6f7c244904ef8",
          "mode": "100644",
          "tree": "46ae7dfad21feead9f34690fbe25d2178488bef0",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Resources/workload.json": {
          "blob": "58a30562798b5cfa04941385f17f6ab6c24c0cff",
          "mode": "100644",
          "tree": "46ae7dfad21feead9f34690fbe25d2178488bef0",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift": {
          "blob": "29169831a6489a84da80c077af6b430b36f683fc",
          "mode": "100644",
          "tree": "46ae7dfad21feead9f34690fbe25d2178488bef0",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift": {
          "blob": "171f496e976904e3a321608645ddc3ddb32f8007",
          "mode": "100644",
          "tree": "46ae7dfad21feead9f34690fbe25d2178488bef0",
          "type": "file"
        },
        "benchmarks/apple/Sources/apple-benchmark/main.swift": {
          "blob": "19fb94e2e330df6445c85f66bec1767b29dd078b",
          "mode": "100644",
          "tree": "46ae7dfad21feead9f34690fbe25d2178488bef0",
          "type": "file"
        },
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift": {
          "blob": "5842dc234fc4be97ceff2ad4d2e1fee6162a0381",
          "mode": "100644",
          "tree": "46ae7dfad21feead9f34690fbe25d2178488bef0",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/README.md",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/1",
      "target_states": {
        "benchmarks/apple/README.md": {
          "blob": "9212b40bdaa6bd0b68630c051d2a558ca665c658",
          "mode": "100644",
          "tree": "c9705ef55ca141aa05d99e5303034e6e6800062f",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift": {
          "blob": "2052c34455151b434778683228806f30d933f225",
          "mode": "100644",
          "tree": "c9705ef55ca141aa05d99e5303034e6e6800062f",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift": {
          "blob": "5f33cd0633dfad15c1932f9b2e790c5459dba836",
          "mode": "100644",
          "tree": "c9705ef55ca141aa05d99e5303034e6e6800062f",
          "type": "file"
        },
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift": {
          "blob": "e08811ca3829221a492c0ca89d0179e4c04ccb24",
          "mode": "100644",
          "tree": "c9705ef55ca141aa05d99e5303034e6e6800062f",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/2",
      "target_states": {
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift": {
          "blob": "32feda8c590c742fbf78a2b90d2be1b239cc7e4a",
          "mode": "100644",
          "tree": "e3f5ee81fd3a69cadc2f6fccc262fb2533dc563e",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift": {
          "blob": "9b435f20f1e26f185a2867d37743b0c070cb18a6",
          "mode": "100644",
          "tree": "e3f5ee81fd3a69cadc2f6fccc262fb2533dc563e",
          "type": "file"
        },
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift": {
          "blob": "bbdd71ccdd3b464accba437e71243c2c8b0838d7",
          "mode": "100644",
          "tree": "e3f5ee81fd3a69cadc2f6fccc262fb2533dc563e",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/3",
      "target_states": {
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift": {
          "blob": "513ba0243fdc76e7f23772ffe9cb6fa92902da54",
          "mode": "100644",
          "tree": "983e8fef7ba2596f022f42b74f4480f0851f8ed2",
          "type": "file"
        },
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift": {
          "blob": "39da7b48d06e64cedb14da46f4c0514f9ff0db3b",
          "mode": "100644",
          "tree": "983e8fef7ba2596f022f42b74f4480f0851f8ed2",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Sources/apple-benchmark/main.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/4",
      "target_states": {
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift": {
          "blob": "b12f8a2c991e5c203dcdd7a60ffae36132595474",
          "mode": "100644",
          "tree": "b87e66277b70d8bf9a86dd5867ef5e76077482ce",
          "type": "file"
        },
        "benchmarks/apple/Sources/apple-benchmark/main.swift": {
          "blob": "6ab8551cc9c4327831486deb848d2ada886c7f13",
          "mode": "100644",
          "tree": "b87e66277b70d8bf9a86dd5867ef5e76077482ce",
          "type": "file"
        },
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift": {
          "blob": "a27de0cc9a7d89c25c1f7fec27030d7efa07a5a9",
          "mode": "100644",
          "tree": "b87e66277b70d8bf9a86dd5867ef5e76077482ce",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/5",
      "target_states": {
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift": {
          "blob": "be2a0ac88b723967dc38373f3b037bfc822c431b",
          "mode": "100644",
          "tree": "d38bb3bd9c10eea23dbfb493108c1ef31eebebf9",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift": {
          "blob": "4b6bfb1d24791383addb9a037eb5b919172d3164",
          "mode": "100644",
          "tree": "d38bb3bd9c10eea23dbfb493108c1ef31eebebf9",
          "type": "file"
        },
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift": {
          "blob": "044e7166e6f62e37bf7225181ae6f867b30c163d",
          "mode": "100644",
          "tree": "d38bb3bd9c10eea23dbfb493108c1ef31eebebf9",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/6",
      "target_states": {
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift": {
          "blob": "0f2faf1e7c89d9cd27e58dde47059a8eb95216b6",
          "mode": "100644",
          "tree": "fa0c491b7c41c2740a33ad7aed14a56d1999d7e0",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift": {
          "blob": "05e3f29549fdd68c4a2019cb3a9ce0e143e70b05",
          "mode": "100644",
          "tree": "fa0c491b7c41c2740a33ad7aed14a56d1999d7e0",
          "type": "file"
        },
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift": {
          "blob": "29660298bd0318af5c52f32f1785ef4a26eaa269",
          "mode": "100644",
          "tree": "fa0c491b7c41c2740a33ad7aed14a56d1999d7e0",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Models.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/7",
      "target_states": {
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Models.swift": {
          "blob": "959fed8e6c363ea2b8795a63ead777ffcd71849a",
          "mode": "100644",
          "tree": "ed4601fb570aa62985480cb30321535774ebc517",
          "type": "file"
        },
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift": {
          "blob": "08079d83fdbdd12d4239cde34bf8d271f19592a2",
          "mode": "100644",
          "tree": "ed4601fb570aa62985480cb30321535774ebc517",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/MockWorkloads.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Models.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift",
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Sources/apple-benchmark/main.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/8",
      "target_states": {
        "benchmarks/apple/Sources/AppleBenchmarkHarness/MockWorkloads.swift": {
          "blob": "523de1315078ea9f7325f05f56ddb452c9c605c0",
          "mode": "100644",
          "tree": "ee3974e766c60b30c2463f478e6c77b98139cc6a",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Models.swift": {
          "blob": "9912a846c4a5984684f7045092aca527d642b16c",
          "mode": "100644",
          "tree": "ee3974e766c60b30c2463f478e6c77b98139cc6a",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift": {
          "blob": "eef0dd904fc94f282430c1968de2dba99956aeba",
          "mode": "100644",
          "tree": "ee3974e766c60b30c2463f478e6c77b98139cc6a",
          "type": "file"
        },
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift": {
          "blob": "8ab313452870747d20aec3f7ed9b4ee4f120ec66",
          "mode": "100644",
          "tree": "ee3974e766c60b30c2463f478e6c77b98139cc6a",
          "type": "file"
        },
        "benchmarks/apple/Sources/apple-benchmark/main.swift": {
          "blob": "ba4a061589d9a3e0d4177e9fb80bece9718e3971",
          "mode": "100644",
          "tree": "ee3974e766c60b30c2463f478e6c77b98139cc6a",
          "type": "file"
        },
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift": {
          "blob": "629a08dc2f3bc71c6ab91f9ba2b1cb09fbf9b4a5",
          "mode": "100644",
          "tree": "ee3974e766c60b30c2463f478e6c77b98139cc6a",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/9",
      "target_states": {
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift": {
          "blob": "49d34b6a96600646d2852faa84adc60850eaf443",
          "mode": "100644",
          "tree": "8fcc84d576e8a3b4c84bd2841105335971511b69",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift",
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/10",
      "target_states": {
        "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift": {
          "blob": "29df536c64cc7213b600d4a6d79543a594bdea38",
          "mode": "100644",
          "tree": "98adb52fd3bd754c17a49904ea716cc9c7f0d71f",
          "type": "file"
        },
        "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift": {
          "blob": "95f7ab973d0390ed4d5f8ca61ee2bdf4939691d8",
          "mode": "100644",
          "tree": "98adb52fd3bd754c17a49904ea716cc9c7f0d71f",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "benchmarks/apple/README.md"
      ],
      "json_pointer": "/ordered_lanes/5/range/source_commits/11",
      "target_states": {
        "benchmarks/apple/README.md": {
          "blob": "5c43ed28683a6329fc3a5e117f2434174a8530bc",
          "mode": "100644",
          "tree": "486c5862adb0df986c46c0d529d43b91710457dc",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/0",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "2b4197aabea486e61d5484c7c7049f81fce83252",
          "mode": "100644",
          "tree": "95bf37e25c5e066f263e047cb99a60f4bc09edf9",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "a7e3126fe8c80e31a82dee91b397193be1be6094",
          "mode": "100644",
          "tree": "95bf37e25c5e066f263e047cb99a60f4bc09edf9",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "3b668e79ede53e2c77f0d366e9075bd5ff917632",
          "mode": "100644",
          "tree": "95bf37e25c5e066f263e047cb99a60f4bc09edf9",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt": {
          "blob": "42aebe7f4422b5bdb1d9f961fa3800c3e2f87387",
          "mode": "100644",
          "tree": "95bf37e25c5e066f263e047cb99a60f4bc09edf9",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence.json": {
          "blob": "6ddfa12da7b787dc97dd3edd5a5099f97094dd90",
          "mode": "100644",
          "tree": "95bf37e25c5e066f263e047cb99a60f4bc09edf9",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/1",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "29a9a22ec445961325ed54b70ab16b46c9ccff21",
          "mode": "100644",
          "tree": "324f8f0b5a80cecb18a415fe32e9195f2b1aa6da",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "c85bea481cc2168dad96e847081891ee09b6f124",
          "mode": "100644",
          "tree": "324f8f0b5a80cecb18a415fe32e9195f2b1aa6da",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "6787aa870f96e98a54fdd020aa9a0d493f1c1f02",
          "mode": "100644",
          "tree": "324f8f0b5a80cecb18a415fe32e9195f2b1aa6da",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt": {
          "blob": "ef9d8a97e53430c4f6666f71700844fa70d3691e",
          "mode": "100644",
          "tree": "324f8f0b5a80cecb18a415fe32e9195f2b1aa6da",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence.json": {
          "blob": "efa0f592e907cb9a5809f79155a3d93aeca06b4f",
          "mode": "100644",
          "tree": "324f8f0b5a80cecb18a415fe32e9195f2b1aa6da",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/2",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "0f03f820a3cc6ede61713d6640ebba55b46271a2",
          "mode": "100644",
          "tree": "c288cba869c9bca1aa36663bdeff99fe2353b5a5",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "017c4ebca16b61cc302618732aee70cd2a94f978",
          "mode": "100644",
          "tree": "c288cba869c9bca1aa36663bdeff99fe2353b5a5",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "9b01a70c5814cf775c581d41c2821ab59d510626",
          "mode": "100644",
          "tree": "c288cba869c9bca1aa36663bdeff99fe2353b5a5",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt": {
          "blob": "11a12e174548f871fd2860563a6b1e486740f4c8",
          "mode": "100644",
          "tree": "c288cba869c9bca1aa36663bdeff99fe2353b5a5",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence.json": {
          "blob": "20636c74aade886a8e50757b6401d81ed9234243",
          "mode": "100644",
          "tree": "c288cba869c9bca1aa36663bdeff99fe2353b5a5",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/3",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "a30014eaa28e0031d765434155381a791d900f5e",
          "mode": "100644",
          "tree": "6413ad4a1ced36166a96362b5901e14d522e299b",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "2ecc88a0a9d4e60d1352705b74a0e34041061d97",
          "mode": "100644",
          "tree": "6413ad4a1ced36166a96362b5901e14d522e299b",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "2ffdd2bb9fcfa805cdace677b316d9f23615cafd",
          "mode": "100644",
          "tree": "6413ad4a1ced36166a96362b5901e14d522e299b",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt": {
          "blob": "34d2589c979f281e1e66df987664cac37900ba34",
          "mode": "100644",
          "tree": "6413ad4a1ced36166a96362b5901e14d522e299b",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence.json": {
          "blob": "172cf6e36f3bec665b138d3bbffc84e922bbee5c",
          "mode": "100644",
          "tree": "6413ad4a1ced36166a96362b5901e14d522e299b",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/4",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "03a5468182668f8f403c7f82e33be7044a4c4e60",
          "mode": "100644",
          "tree": "0e6e402f6ecbc197ff73f8458bfad4b087daa0ce",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "3a6b9a7c2192566cf88760c4fdb7dec12673b606",
          "mode": "100644",
          "tree": "0e6e402f6ecbc197ff73f8458bfad4b087daa0ce",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "d87a60d0534d2dd590bf385eea6973cfb5cd36db",
          "mode": "100644",
          "tree": "0e6e402f6ecbc197ff73f8458bfad4b087daa0ce",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt": {
          "blob": "1575a8950d4545f4ce7d68abeccb272f55035c18",
          "mode": "100644",
          "tree": "0e6e402f6ecbc197ff73f8458bfad4b087daa0ce",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence.json": {
          "blob": "5e01ed2ef4d63cfdb92c9ebb5c57ebf2175a69e0",
          "mode": "100644",
          "tree": "0e6e402f6ecbc197ff73f8458bfad4b087daa0ce",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/5",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "e037f0f52cae322a37a4856f51b23ae9f4de3be7",
          "mode": "100644",
          "tree": "2e19bd7579e57bdbc1594a182ecf9de2e061db28",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "86abc8b96e709b4f7fb37a26be4021c938abed83",
          "mode": "100644",
          "tree": "2e19bd7579e57bdbc1594a182ecf9de2e061db28",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "9896ecb36eea7c3316b5f70f21a143f77d8dcbb2",
          "mode": "100644",
          "tree": "2e19bd7579e57bdbc1594a182ecf9de2e061db28",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt": {
          "blob": "33ad53d209c9079d173e11770c1ffb18b685a5ef",
          "mode": "100644",
          "tree": "2e19bd7579e57bdbc1594a182ecf9de2e061db28",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence.json": {
          "blob": "097c39855e9daa3bf4065e6efe1e75c696f99532",
          "mode": "100644",
          "tree": "2e19bd7579e57bdbc1594a182ecf9de2e061db28",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md",
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/6",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "9af15c24a833b07a5885deb49ca27c57731b4da1",
          "mode": "100644",
          "tree": "b157106959500970ffdff936174840ad1eed5c75",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "a2541829005f0438485812dd46174096e39086a8",
          "mode": "100644",
          "tree": "b157106959500970ffdff936174840ad1eed5c75",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "32ac10c8f48f02b7621fe528ab0f031146d4113a",
          "mode": "100644",
          "tree": "b157106959500970ffdff936174840ad1eed5c75",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt": {
          "blob": "9d9b051c4d0b2cb33402f8171d96e660c13b895f",
          "mode": "100644",
          "tree": "b157106959500970ffdff936174840ad1eed5c75",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence.json": {
          "blob": "7d68c845ec412cbd338369234eaa3f51c74305d4",
          "mode": "100644",
          "tree": "b157106959500970ffdff936174840ad1eed5c75",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/7",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "e359876ea9a5fa9e21c14e2d9831e6b9f3a7b546",
          "mode": "100644",
          "tree": "ba36fc09a68267e3bb26be802040e80e02b0a8a4",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "f862b539e1adef539301f45a6433342d1cf11dc4",
          "mode": "100644",
          "tree": "ba36fc09a68267e3bb26be802040e80e02b0a8a4",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "25a99756a344244d2710971ded81cfdbe935661e",
          "mode": "100644",
          "tree": "ba36fc09a68267e3bb26be802040e80e02b0a8a4",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/8",
      "target_states": {
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt": {
          "blob": "a1fc7592858e734802a35fe7c028f496e6236ca1",
          "mode": "100644",
          "tree": "37998c2c367a12767bd07bf28efb79ecb257b2a7",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence.json": {
          "blob": "5233bfe6c2e7c18321ce4608ff046d98ff3bae51",
          "mode": "100644",
          "tree": "37998c2c367a12767bd07bf28efb79ecb257b2a7",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/9",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "431975888eea154e5aebf339ef5b5a682c1f15d2",
          "mode": "100644",
          "tree": "31d6af0659b7fa964d2ba0a7bcd9f2779659817a",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "418de4043f13d1b2aac2a1be44f6b815dc3b8051",
          "mode": "100644",
          "tree": "31d6af0659b7fa964d2ba0a7bcd9f2779659817a",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "72bf513e57e911224660d5a16d7d7f4781864b73",
          "mode": "100644",
          "tree": "31d6af0659b7fa964d2ba0a7bcd9f2779659817a",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/10",
      "target_states": {
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt": {
          "blob": "2916ea58683eddbba2f293c8947cd4a1df34d634",
          "mode": "100644",
          "tree": "79b8473bb0d16dc628d9316e925b7bc7fa107ca0",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence.json": {
          "blob": "cc9d5d53116cc5837579cba2777a43011bfc2390",
          "mode": "100644",
          "tree": "79b8473bb0d16dc628d9316e925b7bc7fa107ca0",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/11",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "2dba8f43eb2cfbe049f074c9cf3b06fe24a523d6",
          "mode": "100644",
          "tree": "5c3efaa3300e00792fd8fb32bec3e37e336fa111",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "f2d60fe74ff8343ab6c1466ff9f38abcfc2dd657",
          "mode": "100644",
          "tree": "5c3efaa3300e00792fd8fb32bec3e37e336fa111",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "e5710b01b812092d69ae77623b3db32f3a03702b",
          "mode": "100644",
          "tree": "5c3efaa3300e00792fd8fb32bec3e37e336fa111",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt",
        "tests/integration/hermes-traefik/traefik-proof-evidence.json"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/12",
      "target_states": {
        "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt": {
          "blob": "5f8516dcf0acd2279c478815d8f5baf7d65362fc",
          "mode": "100644",
          "tree": "028cf56e0b2c0b526bbaf5b974c60434a5b13555",
          "type": "file"
        },
        "tests/integration/hermes-traefik/traefik-proof-evidence.json": {
          "blob": "c1f6022b239c18cd4d94da84d1001502b3f27cc2",
          "mode": "100644",
          "tree": "028cf56e0b2c0b526bbaf5b974c60434a5b13555",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/13",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "06969e58175ebf7957c153c1d8cc4924a989bb1b",
          "mode": "100644",
          "tree": "6f7be90c699f6a6e35e73bcf144085ba24d7c4e0",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "812f651f643f9761aeb09fe00e651d49f6811c76",
          "mode": "100644",
          "tree": "6f7be90c699f6a6e35e73bcf144085ba24d7c4e0",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "7b7a6c386fdf0a01be2f5c3cfb902e939225bf87",
          "mode": "100644",
          "tree": "6f7be90c699f6a6e35e73bcf144085ba24d7c4e0",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/14",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "b7a32803303312bdfa1b557dfb0f5f426c82b5aa",
          "mode": "100644",
          "tree": "2fa0e2dfee3e0c3ae6bd96860e6c467fd7b7f20f",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "09316e48f85564cb61856a7de8b15f6205bd8b9f",
          "mode": "100644",
          "tree": "2fa0e2dfee3e0c3ae6bd96860e6c467fd7b7f20f",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "4e434509f0c17f159d5dd743e9c47ab7dc7314bc",
          "mode": "100644",
          "tree": "2fa0e2dfee3e0c3ae6bd96860e6c467fd7b7f20f",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/15",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "a06e416ce75da236c4dcfd6a55b4c629029b48b5",
          "mode": "100644",
          "tree": "1a2129de86f127116651c12d747db27f78cde814",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "8c15edf925235819d1987450e4089928b20a2856",
          "mode": "100644",
          "tree": "1a2129de86f127116651c12d747db27f78cde814",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "5c7af7babba7ad3d1d6f1caebea95b51f62ed252",
          "mode": "100644",
          "tree": "1a2129de86f127116651c12d747db27f78cde814",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/16",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "a9c782b893c426dec6ac6d422fa24ed528840ac5",
          "mode": "100644",
          "tree": "13b9baaa63ce3853842fd89f2adf7a8b6a2096fe",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "58303afed2a69b25ebd63da1a842af8051ecebfb",
          "mode": "100644",
          "tree": "13b9baaa63ce3853842fd89f2adf7a8b6a2096fe",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "9b43dc7a5ac4e3ee0b98fb1b37884b1383468d07",
          "mode": "100644",
          "tree": "13b9baaa63ce3853842fd89f2adf7a8b6a2096fe",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/17",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "407f178d14f050605a0a987ab6856843748509e5",
          "mode": "100644",
          "tree": "ee299eb7a8518313a853cb2a37277f2dc28205ef",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "0a3ad3df0a5a7245deda75cbb8a10b7945e4fefc",
          "mode": "100644",
          "tree": "ee299eb7a8518313a853cb2a37277f2dc28205ef",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/18",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "0b521a5cd8efb0c1f9315fd47af20f56a85a1a03",
          "mode": "100644",
          "tree": "b6b4b02bc093eb6140bc334d62ac11dc9ac59461",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "2f2095aeef05f4541155c085061ecf1e4e8fd65e",
          "mode": "100644",
          "tree": "b6b4b02bc093eb6140bc334d62ac11dc9ac59461",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "ae47f205c3c8b8bfb9457b5b55fa7ba5b9ef8b28",
          "mode": "100644",
          "tree": "b6b4b02bc093eb6140bc334d62ac11dc9ac59461",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/19",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "ba7af67c8359267f81938faed8c9f56c5b19d5ef",
          "mode": "100644",
          "tree": "d654f3da44f4e8c702708203c793911a5394aadb",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "02bfa3bdface4ed6b51cb315cd09d3f37174145b",
          "mode": "100644",
          "tree": "d654f3da44f4e8c702708203c793911a5394aadb",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "526464e525c1c5bbc7af90bd2244869ffcde6598",
          "mode": "100644",
          "tree": "d654f3da44f4e8c702708203c793911a5394aadb",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/20",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "2fed5acc1d68060132446825212cf395685c5c5b",
          "mode": "100644",
          "tree": "ac321023238c6271c9e323269254ff44a7053717",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "8435aa6bd653ca3eb89beb0bb49ec80c44aa13ed",
          "mode": "100644",
          "tree": "ac321023238c6271c9e323269254ff44a7053717",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "0325ac6c1a651877a91043846d7da10e71ac0376",
          "mode": "100644",
          "tree": "ac321023238c6271c9e323269254ff44a7053717",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/21",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "c0d991e313932e5aec5163e8e2c7e39aaa1aade3",
          "mode": "100644",
          "tree": "d2489914226288abb313bbefed414f7b2ffd7f82",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "c5ccd8f041eb0e1b2dcf1c4cf26e3798901292a3",
          "mode": "100644",
          "tree": "d2489914226288abb313bbefed414f7b2ffd7f82",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "8936cf04a42942f692595de50e7bf2ee8f291a6a",
          "mode": "100644",
          "tree": "d2489914226288abb313bbefed414f7b2ffd7f82",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/22",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "a0f2ed4bc7d0a767b318bf7a157a6942f539e9b5",
          "mode": "100644",
          "tree": "68eb5367e69745c98116a08b4900c052ad89590e",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "c87b59ad3f7ce39a248b59133d98731dec75470d",
          "mode": "100644",
          "tree": "68eb5367e69745c98116a08b4900c052ad89590e",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "c48d225d0d8a09d1c10a08bce9c570041a4fd161",
          "mode": "100644",
          "tree": "68eb5367e69745c98116a08b4900c052ad89590e",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/23",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "b999242edc0ad15f4ac52f5b87282427db153c3e",
          "mode": "100644",
          "tree": "a4379af320504f3045ce933388debf07e14c3604",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "687d7bd3be6bce442553836290cb7e4500dd4fbf",
          "mode": "100644",
          "tree": "a4379af320504f3045ce933388debf07e14c3604",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "1599686944964e2c8442c6d468f8bf585df3b4b0",
          "mode": "100644",
          "tree": "a4379af320504f3045ce933388debf07e14c3604",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_traefik_proof.py",
        "scripts/traefik_proof.py",
        "tests/integration/hermes-traefik/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/24",
      "target_states": {
        "scripts/test_traefik_proof.py": {
          "blob": "5d803b2d7d186a072789d8c623a1dd4053fb2ceb",
          "mode": "100644",
          "tree": "9efd38c415cfc680146d8577723d8e0c6015eea6",
          "type": "file"
        },
        "scripts/traefik_proof.py": {
          "blob": "5b2c4a6da211c69e79dc9dbca7afa9097b379c22",
          "mode": "100644",
          "tree": "9efd38c415cfc680146d8577723d8e0c6015eea6",
          "type": "file"
        },
        "tests/integration/hermes-traefik/README.md": {
          "blob": "d6d3ea7b34db92c5a0944fe4ab82e198c9712a79",
          "mode": "100644",
          "tree": "9efd38c415cfc680146d8577723d8e0c6015eea6",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/25",
      "target_states": {
        "docs/deployment/README.md": {
          "blob": "788987bbeea9414ddfe0335dbf4d1d4bb024e7f5",
          "mode": "100644",
          "tree": "790f4d731386e2e16df115c20991a98f15dd52bf",
          "type": "file"
        },
        "scripts/README.md": {
          "blob": "06156df5c68271266594f835aa01a8bf0a572c07",
          "mode": "100644",
          "tree": "790f4d731386e2e16df115c20991a98f15dd52bf",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "9dbb68639e2030bb20f771b82786a7c60126a2eb",
          "mode": "100644",
          "tree": "790f4d731386e2e16df115c20991a98f15dd52bf",
          "type": "file"
        },
        "scripts/test_caddy_proof.py": {
          "blob": "4d101cbf577e0737d61e7b6c4d02a84444efd6c8",
          "mode": "100644",
          "tree": "790f4d731386e2e16df115c20991a98f15dd52bf",
          "type": "file"
        },
        "tests/integration/hermes-caddy/README.md": {
          "blob": "07d7ef7586ef1fd09561dfc99be04f05dda5b16c",
          "mode": "100644",
          "tree": "790f4d731386e2e16df115c20991a98f15dd52bf",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "docs/deployment/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/26",
      "target_states": {
        "docs/deployment/README.md": {
          "blob": "2a2033e1ece867669127d1dc7885290c78893662",
          "mode": "100644",
          "tree": "f9bc90ce6db86ed9f91cd49bae3219b35a6141c5",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/27",
      "target_states": {
        "scripts/README.md": {
          "blob": "072e34427ab7de2ccd4e060db41c7b80eed60674",
          "mode": "100644",
          "tree": "88aa9bd56a9cec1b10795b70847b6e636fd7f9a6",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "83fd0c424391bd1c6059498a7523f35d71e0a6e9",
          "mode": "100644",
          "tree": "88aa9bd56a9cec1b10795b70847b6e636fd7f9a6",
          "type": "file"
        },
        "tests/integration/hermes-caddy/README.md": {
          "blob": "7458152323d2b9c1119d4e7ba10767b288807e92",
          "mode": "100644",
          "tree": "88aa9bd56a9cec1b10795b70847b6e636fd7f9a6",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/28",
      "target_states": {
        "docs/deployment/README.md": {
          "blob": "deaf51236bbf1b5a4583db61ed535939d1a003bd",
          "mode": "100644",
          "tree": "8fd0aee1861eab3261f7d5ad8283b5e0aaad938e",
          "type": "file"
        },
        "scripts/README.md": {
          "blob": "342bec3ac63e852f34f3a29c46a2bd4a85c56d5d",
          "mode": "100644",
          "tree": "8fd0aee1861eab3261f7d5ad8283b5e0aaad938e",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "bc6ee14f6daddaf2738147adc7be6b1009d7763c",
          "mode": "100644",
          "tree": "8fd0aee1861eab3261f7d5ad8283b5e0aaad938e",
          "type": "file"
        },
        "scripts/test_caddy_proof.py": {
          "blob": "a19121e7c1f5913073532559b21eb6036aa4be8c",
          "mode": "100644",
          "tree": "8fd0aee1861eab3261f7d5ad8283b5e0aaad938e",
          "type": "file"
        },
        "tests/integration/hermes-caddy/README.md": {
          "blob": "be3ea4ad1d8397de014b5750b592b1103c8261b9",
          "mode": "100644",
          "tree": "8fd0aee1861eab3261f7d5ad8283b5e0aaad938e",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/test_caddy_proof.py"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/29",
      "target_states": {
        "scripts/test_caddy_proof.py": {
          "blob": "46dab959804dd29caaedce5477be470712c80ec5",
          "mode": "100644",
          "tree": "1abb0a48422431c38cb3e4afcb6678da13ddc0d8",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/30",
      "target_states": {
        "docs/deployment/README.md": {
          "blob": "c6295e56bb6ea7e9941d47d6f0b80208304ab8c8",
          "mode": "100644",
          "tree": "468f68c4fcbf9188c7641eafec5db16a5ce6bb2f",
          "type": "file"
        },
        "scripts/README.md": {
          "blob": "297125803648f69d2b97b6fcda6f42cd0d02c27b",
          "mode": "100644",
          "tree": "468f68c4fcbf9188c7641eafec5db16a5ce6bb2f",
          "type": "file"
        },
        "tests/integration/hermes-caddy/README.md": {
          "blob": "c81581e7f70086d2425257c26cc2178c9f71d87d",
          "mode": "100644",
          "tree": "468f68c4fcbf9188c7641eafec5db16a5ce6bb2f",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/31",
      "target_states": {
        "scripts/README.md": {
          "blob": "3ee6c4e37ddd57c595a2688ee46c718f40fa4a4c",
          "mode": "100644",
          "tree": "5dd029807012bc7d26f52205eef97aaf168b736f",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "607112fd4d98592df37bb9c7c33a3764047e004e",
          "mode": "100644",
          "tree": "5dd029807012bc7d26f52205eef97aaf168b736f",
          "type": "file"
        },
        "scripts/test_caddy_proof.py": {
          "blob": "05bcb0ffdebebc3b16e9a645a41498ac4706c644",
          "mode": "100644",
          "tree": "5dd029807012bc7d26f52205eef97aaf168b736f",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/32",
      "target_states": {
        "scripts/README.md": {
          "blob": "9024fd6f8edb4b81127c277b56f4572f30860a2a",
          "mode": "100644",
          "tree": "50ee7ad25f05b8fd4c66f1791b194f3e8d75c310",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "78ed6320f69656393756e3cab864455567fcc697",
          "mode": "100644",
          "tree": "50ee7ad25f05b8fd4c66f1791b194f3e8d75c310",
          "type": "file"
        },
        "scripts/test_caddy_proof.py": {
          "blob": "fc3b441a66061b09f2b0267f7813193838884428",
          "mode": "100644",
          "tree": "50ee7ad25f05b8fd4c66f1791b194f3e8d75c310",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/33",
      "target_states": {
        "docs/deployment/README.md": {
          "blob": "8980bf2cd3f51c643d0dd09b2a572212e2e58667",
          "mode": "100644",
          "tree": "0ecee2249a377a4599c812d5bddb7d44f5e0ea77",
          "type": "file"
        },
        "scripts/README.md": {
          "blob": "90e7291440f4d7757a07203aceda1dbf111491b9",
          "mode": "100644",
          "tree": "0ecee2249a377a4599c812d5bddb7d44f5e0ea77",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "cc01bd785654ced84aef0292d16c89055e48dddb",
          "mode": "100644",
          "tree": "0ecee2249a377a4599c812d5bddb7d44f5e0ea77",
          "type": "file"
        },
        "scripts/test_caddy_proof.py": {
          "blob": "e6db431f4db0f48d9c32fe4b8f80b9ecbcedd3c9",
          "mode": "100644",
          "tree": "0ecee2249a377a4599c812d5bddb7d44f5e0ea77",
          "type": "file"
        },
        "tests/integration/hermes-caddy/README.md": {
          "blob": "5d5a0bdf5490ea356279d6f911a94d53ef6811df",
          "mode": "100644",
          "tree": "0ecee2249a377a4599c812d5bddb7d44f5e0ea77",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/34",
      "target_states": {
        "docs/deployment/README.md": {
          "blob": "35e05718c493d2cb1a4f138d2f7317ed1f124b47",
          "mode": "100644",
          "tree": "c74d955f8e892624283433f3ac7a74296218d93f",
          "type": "file"
        },
        "scripts/README.md": {
          "blob": "e379e0d2f79a4c638d667205529f0103db56ff85",
          "mode": "100644",
          "tree": "c74d955f8e892624283433f3ac7a74296218d93f",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "6decd1e7b0b63f7111220d0cf5fde7aefcc78797",
          "mode": "100644",
          "tree": "c74d955f8e892624283433f3ac7a74296218d93f",
          "type": "file"
        },
        "scripts/test_caddy_proof.py": {
          "blob": "d85ec8d6d11049aabe0b1ebf2c852b9fb7cc2150",
          "mode": "100644",
          "tree": "c74d955f8e892624283433f3ac7a74296218d93f",
          "type": "file"
        },
        "tests/integration/hermes-caddy/README.md": {
          "blob": "629aa3ae42888c279559def25d0b7796512e0863",
          "mode": "100644",
          "tree": "c74d955f8e892624283433f3ac7a74296218d93f",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/35",
      "target_states": {
        "docs/deployment/README.md": {
          "blob": "6d7ae54f93e294f0b01e2db094da13bfd7a90cd1",
          "mode": "100644",
          "tree": "9304d895bba7601f9ffa6f3c690fb573f7a7558d",
          "type": "file"
        },
        "scripts/README.md": {
          "blob": "83fa47104014d93506cbf07d8ccc3b5cf10955a7",
          "mode": "100644",
          "tree": "9304d895bba7601f9ffa6f3c690fb573f7a7558d",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "d75819ccaaf6a8f91592b6c52abd39975b53242e",
          "mode": "100644",
          "tree": "9304d895bba7601f9ffa6f3c690fb573f7a7558d",
          "type": "file"
        },
        "scripts/test_caddy_proof.py": {
          "blob": "40f2759c1f7aae0dda7bae3f25cfadaae2a1bb1f",
          "mode": "100644",
          "tree": "9304d895bba7601f9ffa6f3c690fb573f7a7558d",
          "type": "file"
        },
        "tests/integration/hermes-caddy/README.md": {
          "blob": "033f1173a657ff3a930407faf4b78fab47fda97a",
          "mode": "100644",
          "tree": "9304d895bba7601f9ffa6f3c690fb573f7a7558d",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/36",
      "target_states": {
        "docs/deployment/README.md": {
          "blob": "2a5b3cd238758feeb0afba4f00a1ffdc6f62e5d3",
          "mode": "100644",
          "tree": "bf850d5559d1e218174e020d4ae3c29d5a55b5e8",
          "type": "file"
        },
        "scripts/README.md": {
          "blob": "dc8d2a594c8b3cb63444d7ed569370353da75c43",
          "mode": "100644",
          "tree": "bf850d5559d1e218174e020d4ae3c29d5a55b5e8",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "8b097f31729e7aebeeef219f258fc1dc42de1767",
          "mode": "100644",
          "tree": "bf850d5559d1e218174e020d4ae3c29d5a55b5e8",
          "type": "file"
        },
        "scripts/test_caddy_proof.py": {
          "blob": "2c16edf0415a5794151b10c0fc4ba2b9ba410063",
          "mode": "100644",
          "tree": "bf850d5559d1e218174e020d4ae3c29d5a55b5e8",
          "type": "file"
        },
        "tests/integration/hermes-caddy/README.md": {
          "blob": "e4c8467a60885813aa4f51012dd2b151f1f36853",
          "mode": "100644",
          "tree": "bf850d5559d1e218174e020d4ae3c29d5a55b5e8",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/37",
      "target_states": {
        "docs/deployment/README.md": {
          "blob": "4fedc47045f93eeafeca254ce54b985122e7eff6",
          "mode": "100644",
          "tree": "5a0662edb18a4f0c4985aff1ccb4307bc85b0f84",
          "type": "file"
        },
        "scripts/README.md": {
          "blob": "1c65b9419cd5443b9ad972c4e4b621c5807f729b",
          "mode": "100644",
          "tree": "5a0662edb18a4f0c4985aff1ccb4307bc85b0f84",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "27409bdf7edd1d3169035f01f0a643bed539ea83",
          "mode": "100644",
          "tree": "5a0662edb18a4f0c4985aff1ccb4307bc85b0f84",
          "type": "file"
        },
        "scripts/test_caddy_proof.py": {
          "blob": "5969d1357e12ff612634d48128159fb7d6ee095d",
          "mode": "100644",
          "tree": "5a0662edb18a4f0c4985aff1ccb4307bc85b0f84",
          "type": "file"
        },
        "tests/integration/hermes-caddy/README.md": {
          "blob": "5714cd71c61e21cd687d99c17ecbc2357a546232",
          "mode": "100644",
          "tree": "5a0662edb18a4f0c4985aff1ccb4307bc85b0f84",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/38",
      "target_states": {
        "docs/deployment/README.md": {
          "blob": "7193361969b9654134095de311eabec5731555ea",
          "mode": "100644",
          "tree": "2f071824439b4e37ab1d52937693059527b9c8ac",
          "type": "file"
        },
        "scripts/README.md": {
          "blob": "a89837521c0be74827087261f23c77b5a22ec2a1",
          "mode": "100644",
          "tree": "2f071824439b4e37ab1d52937693059527b9c8ac",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "fc96e06b8bc6432798c5fa28edfb20963b2c9084",
          "mode": "100644",
          "tree": "2f071824439b4e37ab1d52937693059527b9c8ac",
          "type": "file"
        },
        "scripts/test_caddy_proof.py": {
          "blob": "fd5ec6655ffa18eefb9de050aaca9ab4b076424d",
          "mode": "100644",
          "tree": "2f071824439b4e37ab1d52937693059527b9c8ac",
          "type": "file"
        },
        "tests/integration/hermes-caddy/README.md": {
          "blob": "fe58ae8ca11d8dfe58be6c1fc13675dfe38dd292",
          "mode": "100644",
          "tree": "2f071824439b4e37ab1d52937693059527b9c8ac",
          "type": "file"
        }
      }
    },
    {
      "changed_paths": [
        "docs/deployment/README.md",
        "scripts/README.md",
        "scripts/caddy_proof.py",
        "scripts/test_caddy_proof.py",
        "tests/integration/hermes-caddy/README.md"
      ],
      "json_pointer": "/ordered_lanes/6/range/source_commits/39",
      "target_states": {
        "docs/deployment/README.md": {
          "blob": "4bd600740e3d5da917830fe7dd04cbd595e64ea9",
          "mode": "100644",
          "tree": "2c0bf65970fa7368557fabf803e226894b6d4574",
          "type": "file"
        },
        "scripts/README.md": {
          "blob": "c2a31b8b58237551b698c64671a027da28ed84ff",
          "mode": "100644",
          "tree": "2c0bf65970fa7368557fabf803e226894b6d4574",
          "type": "file"
        },
        "scripts/caddy_proof.py": {
          "blob": "7e3e82cf925c6d4dd03daa72f145014964458dc3",
          "mode": "100644",
          "tree": "2c0bf65970fa7368557fabf803e226894b6d4574",
          "type": "file"
        },
        "scripts/test_caddy_proof.py": {
          "blob": "c5fb75eee55a0b1ddc3698a42016358c8f79254b",
          "mode": "100644",
          "tree": "2c0bf65970fa7368557fabf803e226894b6d4574",
          "type": "file"
        },
        "tests/integration/hermes-caddy/README.md": {
          "blob": "0d48fc36e0ba5a4899f416e18f71303b4939c678",
          "mode": "100644",
          "tree": "2c0bf65970fa7368557fabf803e226894b6d4574",
          "type": "file"
        }
      }
    }
  ]
}
<!-- candidate-five non-authority fence boundary -->
