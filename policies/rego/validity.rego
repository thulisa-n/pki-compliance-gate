package pki.compliance

# Optional OPA policy gate.
# This is evaluated only when opa.enabled=true in the active policy file.
default allow := false

allow if {
    input.validity_days <= 200
}
