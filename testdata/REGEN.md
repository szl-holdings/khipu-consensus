# Regenerating TEST-ONLY keypairs

The deterministic vector tests in [`vectors.json`](vectors.json) embed the **public**
keys of four witnesses (`a11oy`, `amaru`, `killinchu`, `sentra`). The matching
public keys are also kept here as `*.test.pub` for convenience.

The corresponding **private** keys are intentionally **NOT committed** (doctrine:
never commit a private key, even a throwaway test one). They are not needed to run
the vector suite — the tests only *verify* signatures against the public keys.

If you need to (re)sign new vectors locally, generate a fresh throwaway P-256
keypair and keep the private half out of git:

```bash
# private key (DO NOT COMMIT — add to .gitignore if you create one)
openssl ecparam -name prime256v1 -genkey -noout -out witness.test.key
# matching public key (safe to publish)
openssl ec -in witness.test.key -pubout -out witness.test.pub
```

Then use `sign_verdict(...)` (Python) or the TypeScript `sign` helper to produce a
fresh DSSE-signed verdict, and replace the relevant `signatures` entry plus the
`pubkeys.<witness>` value in `vectors.json`. The Go implementation is verify-only.

> TEST-ONLY. Never use these keys, or any key generated this way, in production.
> Production witnesses run their own governance brains and publish their own keys.
