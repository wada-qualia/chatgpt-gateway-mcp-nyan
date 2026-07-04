package gateway

default allow := false

roles := {role |
  some i
  role := input.subject.realm_access.roles[i]
}

allow if {
  "gateway-admin" in roles
}

allow if {
  input.resource.action == "read"
  "gateway-user" in roles
}

allow if {
  input.resource.owner == input.subject.sub
  input.resource.action in {"read", "create", "update"}
  "gateway-user" in roles
}

allow if {
  input.resource.action == "read_audit"
  "gateway-auditor" in roles
}
