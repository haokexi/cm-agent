package selfupdate

import "testing"

func TestTagCandidates(t *testing.T) {
	got := tagCandidates("0.1.2")
	if len(got) != 2 || got[0] != "0.1.2" || got[1] != "v0.1.2" {
		t.Fatalf("unexpected candidates: %#v", got)
	}
}

func TestSameVersion(t *testing.T) {
	if !sameVersion("v1.2.3", "1.2.3") {
		t.Fatal("expected versions to match")
	}
	if sameVersion("1.2.3", "1.2.4") {
		t.Fatal("expected versions to differ")
	}
}

func TestReleaseNames(t *testing.T) {
	asset, bin, err := releaseNames("linux", "amd64")
	if err != nil {
		t.Fatalf("release names error: %v", err)
	}
	if asset != "cm-agent-linux-amd64.tgz" || bin != "cm-agent-linux-amd64" {
		t.Fatalf("unexpected names: asset=%s bin=%s", asset, bin)
	}
}
