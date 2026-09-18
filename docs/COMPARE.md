# When to use CertGuard, zlint, and `openssl verify`

These tools answer different questions. Running all three is normal. Substituting one for another is how pipelines go green for the wrong reason.

| Question | Tool |
| :--- | :--- |
| Does this encoding match RFC 5280 / CA/B Forum lint rules? | [zlint](https://github.com/zmap/zlint) |
| Does this chain verify to a trust anchor, and is it revoked? | `openssl verify` (CRL/OCSP as you configure them) |
| Does this certificate (or CSR) match **our** YAML profile in **this** CI run, with evidence? | `pki-gate` |

CertGuard is Policy-as-Code plus an exit code. The YAML profile is allowed to be stricter or looser than a linter. Disabled controls are `not_applicable`, never a silent pass.

CertGuard does **not** build a certification path, check CRLs/OCSP, or claim full Baseline Requirements conformance. Optional zlint/`asn1parse` overlays exist in policy; they are off on the default profile so a missing binary cannot fail a run that never asked for lint.

### Suggested pipeline order

1. `pki-gate --csr` before the CA signs (key, SAN, internal names).
2. CA issues the certificate.
3. `pki-gate --cert` on the issued PEM (validity, serial, profile).
4. `openssl verify` against your trust store.
5. `zlint` if you want encoding lint in addition to policy.

Related: [examples/pre-issuance](../examples/pre-issuance/), [corpus/verdicts.yaml](../corpus/verdicts.yaml).
