# OPA/Rego port of tracegate/policy.py (same rules, same verdicts).
#   tracegate opa-input events.json > input.json
#   opa eval -f pretty -i input.json -d policies/ 'data.tracegate.decision'
# CI checks that this policy and the Python DSL agree on every demo scenario.
package tracegate

import rego.v1

scanners := {"trivy", "grype", "osv"}

high_plus := {"high", "critical"}

reasons contains r if {
	some msg in input.rejected
	r := {"rule": "provenance_integrity", "verdict": "block", "msg": msg}
}

reasons contains r if {
	count(input.missing_stages) > 0
	r := {"rule": "provenance_integrity", "verdict": "block",
	      "msg": sprintf("missing signed provenance for stages %v", [input.missing_stages])}
}

reasons contains r if {
	some f in input.findings
	f.source == "warden"
	v := "block" if f.severity == "critical" else := "warn"
	r := {"rule": "malicious_dependency", "verdict": v, "finding": f.id}
}

reasons contains r if {
	some f in input.findings
	f.source in scanners
	f.severity in high_plus
	v := "warn" if f.reachable == false else := "block"
	r := {"rule": "vulnerable_dependency", "verdict": v, "finding": f.id}
}

reasons contains r if {
	some f in input.findings
	f.source in scanners
	f.severity == "medium"
	r := {"rule": "vulnerable_dependency", "verdict": "warn", "finding": f.id}
}

reasons contains r if {
	some f in input.findings
	f.source == "sast"
	f.severity in {"medium", "high", "critical"}
	v := "block" if f.severity in high_plus else := "warn"
	r := {"rule": "sast", "verdict": v, "finding": f.id}
}

verdict := "block" if {
	some r in reasons
	r.verdict == "block"
} else := "warn" if {
	some r in reasons
	r.verdict == "warn"
} else := "pass"

decision := {"verdict": verdict, "reasons": reasons}
