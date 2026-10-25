package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

const topo = "../../testdata/topologies"

func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func snap(name string) string { return filepath.Join(topo, name, "snapshot.json") }

// TestGoldenReports pins the exact Markdown and JSON output for fixtures.
func TestGoldenReports(t *testing.T) {
	cases := []struct {
		golden string
		args   []string
	}{
		{"public-web.md", []string{"analyze", "-s", snap("public-web")}},
		{"public-web.json", []string{"analyze", "-s", snap("public-web"), "-format", "json"}},
		{"nacl-ordering.md", []string{"analyze", "-s", snap("nacl-ordering")}},
		{"nat-egress-egress.md", []string{"analyze", "-s", snap("nat-egress"), "-egress", "-from", "all"}},
		{"peering-from-a.md", []string{"analyze", "-s", snap("peering"), "-from", "eni-a"}},
		{"why-nat.txt", []string{"why", "-s", snap("nat-egress"), "-from", "eni-worker", "-to", "8.8.8.8",
			"-proto", "tcp", "-port", "443", "-sport", "40000"}},
		{"why-nacl.txt", []string{"why", "-s", snap("nacl-ordering"), "-from", "198.51.100.20", "-to", "eni-vpn",
			"-proto", "tcp", "-port", "22", "-sport", "40000"}},
	}
	for _, c := range cases {
		t.Run(c.golden, func(t *testing.T) {
			out, errOut, code := run(t, c.args...)
			if code != ExitOK {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			path := filepath.Join("testdata", "golden", c.golden)
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/cli -update)", err)
			}
			if out != string(want) {
				t.Fatalf("output differs from %s; run with -update after reviewing:\n%s", path, out)
			}
		})
	}
}

func TestCommands(t *testing.T) {
	tmp := t.TempDir()
	genPath := filepath.Join(tmp, "gen.json")
	reportPath := filepath.Join(tmp, "r.json")
	cases := []struct {
		name     string
		args     []string
		code     int
		contains string
	}{
		{"no args", nil, ExitUsage, ""},
		{"help", []string{"help"}, ExitOK, "Usage:"},
		{"version", []string{"version"}, ExitOK, "netreach 0.1.0"},
		{"unknown", []string{"frobnicate"}, ExitUsage, ""},
		{"flag help", []string{"analyze", "-h"}, ExitOK, ""},
		{"bad flag", []string{"analyze", "-nope"}, ExitUsage, ""},
		{"extra args", []string{"validate", "-s", snap("peering"), "extra"}, ExitUsage, ""},
		{"missing snapshot flag", []string{"validate"}, ExitUsage, ""},
		{"missing file", []string{"validate", "-s", "nope.json"}, ExitFailure, ""},
		{"validate", []string{"validate", "-s", snap("peering")}, ExitOK, "ok: peering: 3 VPCs"},
		{"verify", []string{"verify", "-dir", topo}, ExitOK, "total"},
		{"verify missing dir", []string{"verify", "-dir", "nope"}, ExitFailure, ""},
		{"bad format", []string{"analyze", "-s", snap("peering"), "-format", "xml"}, ExitUsage, ""},
		{"bad fail-on", []string{"analyze", "-s", snap("peering"), "-fail-on", "critical"}, ExitUsage, ""},
		{"fail-on triggers", []string{"analyze", "-s", snap("nacl-ordering"), "-fail-on", "high"}, ExitFindings, ""},
		{"fail-on quiet", []string{"analyze", "-s", snap("public-web"), "-fail-on", "medium"}, ExitOK, ""},
		{"cidr sources", []string{"analyze", "-s", snap("public-web"), "-from", "203.0.113.0/24,198.51.100.0/24"}, ExitOK, "22,80,443"},
		{"bad cidr", []string{"analyze", "-s", snap("public-web"), "-from", "1.2.3.4/99"}, ExitUsage, ""},
		{"target filter", []string{"analyze", "-s", snap("public-web"), "-target", "i-web1"}, ExitOK, "1 analysed"},
		{"bad target", []string{"analyze", "-s", snap("public-web"), "-target", "eni-zzz"}, ExitUsage, ""},
		{"egress one", []string{"analyze", "-s", snap("nat-egress"), "-egress", "-from", "eni-worker", "-to", "8.8.8.0/24"}, ExitOK, "8.8.8.0/24"},
		{"egress bad to", []string{"analyze", "-s", snap("nat-egress"), "-egress", "-from", "eni-worker", "-to", "x"}, ExitUsage, ""},
		{"egress bad from", []string{"analyze", "-s", snap("nat-egress"), "-egress", "-from", "eni-nope"}, ExitUsage, ""},
		{"write file", []string{"analyze", "-s", snap("public-web"), "-format", "json", "-o", reportPath}, ExitOK, ""},
		{"write bad path", []string{"analyze", "-s", snap("public-web"), "-o", filepath.Join(tmp, "no", "dir.md")}, ExitFailure, ""},
		{"why internal", []string{"why", "-s", snap("peering"), "-from", "eni-a", "-to", "eni-b", "-port", "6379"}, ExitOK, "BLOCKED"},
		{"why same eni", []string{"why", "-s", snap("peering"), "-from", "eni-a", "-to", "eni-a"}, ExitUsage, ""},
		{"why egress", []string{"why", "-s", snap("nat-egress"), "-from", "eni-worker", "-to", "8.8.8.8", "-proto", "udp", "-port", "53"}, ExitOK, "ALLOWED"},
		{"why egress bad ip", []string{"why", "-s", snap("nat-egress"), "-from", "eni-worker", "-to", "x"}, ExitUsage, ""},
		{"why bad source", []string{"why", "-s", snap("nat-egress"), "-from", "x", "-to", "eni-worker"}, ExitUsage, ""},
		{"why unknown target", []string{"why", "-s", snap("nat-egress"), "-from", "1.2.3.4", "-to", "eni-x"}, ExitUsage, ""},
		{"why icmp", []string{"why", "-s", snap("nacl-ordering"), "-from", "192.0.2.1", "-to", "eni-vpn", "-proto", "icmp"}, ExitOK, "ALLOWED"},
		{"why bad proto", []string{"why", "-s", snap("nacl-ordering"), "-from", "192.0.2.1", "-to", "eni-vpn", "-proto", "all"}, ExitUsage, ""},
		{"why bad port", []string{"why", "-s", snap("nacl-ordering"), "-from", "192.0.2.1", "-to", "eni-vpn", "-port", "70000"}, ExitUsage, ""},
		{"gen", []string{"gen", "-seed", "3", "-o", genPath}, ExitOK, ""},
		{"gen invalid", []string{"gen", "-vpcs", "0"}, ExitUsage, ""},
		{"gen stdout", []string{"gen", "-seed", "4", "-vpcs", "1", "-subnets", "1", "-enis", "1"}, ExitOK, `"generated-4"`},
		{"bench", []string{"bench", "-sizes", "1", "-depths", "2", "-repeats", "1"}, ExitOK, "| 1 VPCs |"},
		{"bench bad sizes", []string{"bench", "-sizes", "x"}, ExitUsage, ""},
		{"bench bad depths", []string{"bench", "-depths", "0"}, ExitUsage, ""},
		{"bench bad repeats", []string{"bench", "-repeats", "0"}, ExitUsage, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, errOut, code := run(t, c.args...)
			if code != c.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, c.code, out, errOut)
			}
			if c.contains != "" && !strings.Contains(out, c.contains) {
				t.Fatalf("stdout lacks %q:\n%s", c.contains, out)
			}
		})
	}
	// The generated snapshot must itself validate.
	if out, errOut, code := run(t, "validate", "-s", genPath); code != ExitOK {
		t.Fatalf("generated snapshot invalid: %s %s", out, errOut)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidSnapshotIsUsageError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"name":"bad","vpcs":[{"id":"vpc-1","cidrs":["10.0.0.0/33"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := run(t, "validate", "-s", path)
	if code != ExitUsage || !strings.Contains(errOut, "bad prefix length") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestInstanceWithSeveralENIsIsAmbiguous(t *testing.T) {
	raw, err := os.ReadFile(snap("multi-sg"))
	if err != nil {
		t.Fatal(err)
	}
	// Give two interfaces the same instance ID.
	text := strings.Replace(string(raw), `"name": "admin-1",`, `"name": "admin-1", "instance": "i-dup",`, 1)
	text = strings.Replace(text, `"name": "admin-2",`, `"name": "admin-2", "instance": "i-dup",`, 1)
	path := filepath.Join(t.TempDir(), "dup.json")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := run(t, "analyze", "-s", path, "-from", "i-dup")
	if code != ExitUsage || !strings.Contains(errOut, "has 2 interfaces") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestWriteFailureIsReported(t *testing.T) {
	var errOut bytes.Buffer
	if code := Run([]string{"version"}, failingWriter{}, &errOut); code != ExitFailure {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errOut.String(), "write output") {
		t.Fatal(errOut.String())
	}
}
