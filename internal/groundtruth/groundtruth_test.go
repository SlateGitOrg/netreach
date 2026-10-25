package groundtruth

import (
	"testing"
)

const fixtureRoot = "../../testdata/topologies"

func TestFixturesMatchGroundTruth(t *testing.T) {
	fixtures, err := LoadDir(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < 6 {
		t.Fatalf("expected at least 6 fixtures, found %d", len(fixtures))
	}
	for _, fx := range fixtures {
		t.Run(fx.Name, func(t *testing.T) {
			out := Check(fx)
			if out.Probes == 0 {
				t.Fatal("fixture has no probes")
			}
			for _, f := range out.Failures {
				t.Error(f)
			}
			t.Logf("%d checks, %d probes", out.Checks, out.Probes)
		})
	}
}
