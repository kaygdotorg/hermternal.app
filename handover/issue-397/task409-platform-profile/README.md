# Linux platform profile successor

This directory defines the only mutable host contract for the issue #397
guarded replay. `linux-host-v1.json` is a build-time profile. Runtime
environment variables cannot override it.

`platform_successor.py` verified-loads approved #401, #402, and #403 code. It
derives one Linux triad and publishes it create-only. The generated JSON,
Markdown, and shell repeat profile literals because their cross-format bytes
must agree. The closed adaptation manifest records predecessor hashes, the two
semantic host changes, the dependent temporary-parent derivation, and unchanged
replay semantics.

`linux_retained_driver.py` verified-loads the reviewed retained-driver
transform. `linux_replay_wrapper.py` pins the reviewed outer wrapper to the new
driver contract. It is a read-only preflight and cannot run replay. New Phase A
v3 evidence is required before replay authorization.

Run:

```sh
/usr/bin/python3 -B test_platform_profile.py
/usr/bin/python3 -O -B test_platform_profile.py
/usr/bin/python3 -B platform_successor.py --prepare
/usr/bin/python3 -B linux_replay_wrapper.py
```

Do not run `--publish` again. The durable final set already exists and a second
publication must fail. No tool in this directory executes the generated shell,
Git replay, Hermes, network access, or credentials.
