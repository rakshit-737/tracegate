# OPA/Rego port of tracegate/policy.py (same rules, same verdicts).
#   tracegate export events.json --format opa > input.json
#   opa eval -f pretty -i input.json -d policies/ 'data.tracegate.decision'
# CI (scripts/opa_parity.py) checks this policy and the Python DSL agree on every demo scenario.
package tracegate

import rego.v1

scanners := {"trivy", "grype", "osv"}

high_plus := {"high", "critical"}

medium_plus := {"medium", "high", "critical"}

warden_verdict(sev) := "block" if sev == "critical"

warden_verdict(sev) := "warn" if sev != "critical"

vuln_verdict(f) := "warn" if f.reachable == false

vuln_verdict(f) := "block" if f.reachable != false

sast_verdict(sev) := "block" if sev in high_plus

sast_verdict(sev) := "warn" if not sev in high_plus

reasons contains r if {
	some msg in input.rejected
	r := {"rule": "provenance_integrity", "verdict": "block", "msg": msg}
}

reasons contains r if {
	count(input.missing_stages) > 0
	r := {
		"rule": "provenance_integrity", "verdict": "block",
		"msg": sprintf("missing signed provenance for stages %v", [input.missing_stages]),
	}
}

reasons contains r if {
	some f in input.findings
	f.source == "warden"
	r := {"rule": "malicious_dependency", "verdict": warden_verdict(f.severity), "finding": f.id}
}

reasons contains r if {
	some f in input.findings
	f.source in scanners
	f.severity in high_plus
	r := {"rule": "vulnerable_dependency", "verdict": vuln_verdict(f), "finding": f.id}
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
	f.severity in medium_plus
	r := {"rule": "sast", "verdict": sast_verdict(f.severity), "finding": f.id}
}

default verdict := "pass"

verdict := "block" if {
	some r in reasons
	r.verdict == "block"
}

verdict := "warn" if {
	not any_block
	some r in reasons
	r.verdict == "warn"
}

any_block if {
	some r in reasons
	r.verdict == "block"
}

decision := {"verdict": verdict, "reasons": reasons}
