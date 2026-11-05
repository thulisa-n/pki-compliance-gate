# Neakam collects nothing

Neakam does not collect, store, or send telemetry. There is no analytics
endpoint, no phone-home, no update check, and no crash reporter.

`neakam` reads certificates, CSRs, and policy files you pass on the command
line, and it writes reports only to paths you choose. `neakam doctor` is an
offline self-test. It does not use the network.

The deprecated `pki-gate` and `certguard` commands behave the same way. They
print a one-line deprecation notice to stderr and do not add any network use.

## The only network use

A live TLS posture check is off unless you opt in:

```bash
neakam --mode apisec --allow-network --endpoint https://api.example.com
```

That check:

- opens one TLS connection to each host you list with `--endpoint` (repeat the flag to list more than one)
- uses a timeout (`--network-timeout`, default 10 seconds, maximum 30)
- reads the peer certificate, negotiated TLS version, and cipher suite
- does not follow redirects to any other host, and does not speak HTTP
- does not send certificate contents, policy, or a telemetry payload anywhere

`--allow-network` does nothing in other modes. Passing it with `--cert` does
not open a connection.

Setting `endpoint` on the GitHub Action with `mode: apisec` is the same opt-in:
the Action adds `--allow-network` only in that case.

## Maintainer script

`scripts/sync_cabf_baseline.py` is not installed as a console script. It
downloads a public CA/Browser Forum document only when `--fetch` is passed,
only from the host in `--source-url`, with a 30 second timeout, and it refuses
redirects to a different host. The scheduled workflow passes `--fetch`
explicitly. Use `--source-file` for an offline run.

## How this is enforced

`tests/test_no_network.py` blocks socket creation and connections while the
main CLI paths run on fixture certificates. Any outbound attempt fails that
test. The live TLS check is exempt only when `--allow-network` is set, and
only for the hosts named by `--endpoint`.
