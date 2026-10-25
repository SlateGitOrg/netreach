package topogen

import (
	"encoding/json"
	"testing"

	"github.com/archit2501/netreach/model"
)

func TestGeneratedSnapshotsAlwaysCompile(t *testing.T) {
	for seed := uint64(0); seed < 300; seed++ {
		p := Small(seed)
		if seed%3 == 0 {
			p.VPCs, p.SubnetsPerVPC, p.ACLRules = 4, 3, 12
		}
		snap, err := Generate(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := model.Compile(snap); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	a, _ := Generate(Small(42))
	b, _ := Generate(Small(42))
	c, _ := Generate(Small(43))
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	jc, _ := json.Marshal(c)
	if string(ja) != string(jb) || string(ja) == string(jc) {
		t.Fatal("generation must depend only on params")
	}
}

func TestValidateBounds(t *testing.T) {
	bad := []func(*Params){
		func(p *Params) { p.VPCs = 0 },
		func(p *Params) { p.VPCs = 201 },
		func(p *Params) { p.SubnetsPerVPC = 0 },
		func(p *Params) { p.ENIsPerSubnet = 500 },
		func(p *Params) { p.SGsPerVPC = 0 },
		func(p *Params) { p.ACLRules = -1 },
	}
	for i, mutate := range bad {
		p := Small(1)
		mutate(&p)
		if _, err := Generate(p); err == nil {
			t.Errorf("case %d: invalid params accepted", i)
		}
	}
}
