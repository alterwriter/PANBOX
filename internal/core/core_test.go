package core

import "testing"

func TestFingerprintStableAcrossLineChanges(t *testing.T) {
	a := Fingerprint("vaccin", "rule", `src\login.py`, " SQL   query built from input ")
	b := Fingerprint("vaccin", "rule", "src/login.py", "SQL query built from input")
	if a != b {
		t.Fatalf("fingerprint should normalize path and whitespace: %q != %q", a, b)
	}
	if a == Fingerprint("vaccin", "other", "src/login.py", "SQL query built from input") {
		t.Fatal("rule must participate in identity")
	}
}
func TestBranchDeltaAndGate(t *testing.T) {
	if Delta(false, false) != "baseline_unknown" || Delta(true, false) != "new" || Delta(true, true) != "existing" {
		t.Fatal("invalid branch delta")
	}
	if pass, err := Gate("partial", nil); err == nil || pass {
		t.Fatal("partial scan cannot pass")
	}
	if pass, err := Gate("complete", []string{"medium"}); err != nil || !pass {
		t.Fatal("medium should pass default policy")
	}
	if pass, err := Gate("complete", []string{"high"}); err != nil || pass {
		t.Fatal("high should fail default policy")
	}
}
