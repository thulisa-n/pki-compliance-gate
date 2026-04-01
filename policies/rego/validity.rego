package pki.compliance

# Optional OPA policy gate.
# This is evaluated only when policy.opa.enabled=true.
default allow := false

allow if {
    input.validity_days <= 200
}
