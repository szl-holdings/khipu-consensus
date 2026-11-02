// SPDX-License-Identifier: Apache-2.0
package khipuconsensus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vectorFile struct {
	ActionHash string            `json:"action_hash"`
	Threshold  int               `json:"threshold"`
	N          int               `json:"n"`
	Pubkeys    map[string]string `json:"pubkeys"`
	Cases      []struct {
		Name   string `json:"name"`
		Expect struct {
			Decision       string `json:"decision"`
			ConsensusCount int    `json:"consensus_count"`
		} `json:"expect"`
		Signatures []*OrganVerdict `json:"signatures"`
	} `json:"cases"`
}

func TestVectors(t *testing.T) {
	checkVectors(t, "vectors.json")
}

func TestDomainAndIdentityBindingVectors(t *testing.T) {
	checkVectors(t, "domain-identity-binding.json")
}

func checkVectors(t *testing.T, name string) {
	t.Helper()
	path := filepath.Join("..", "testdata", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	for _, c := range vf.Cases {
		r := Tally(vf.ActionHash, c.Signatures, vf.Pubkeys, vf.Threshold, vf.N)
		if r.Decision != c.Expect.Decision || r.ConsensusCount != c.Expect.ConsensusCount {
			t.Errorf("[FAIL] %s: got %s %s, want %s %d-of-%d", c.Name, r.KhipuConsensus,
				r.Decision, c.Expect.Decision, c.Expect.ConsensusCount, vf.N)
		} else {
			t.Logf("[PASS] %s: %s -> %s", c.Name, r.KhipuConsensus, r.Decision)
		}
	}
}

func TestQuorumCounts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var source vectorFile
	if err := json.Unmarshal(raw, &source); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join("..", "testdata", "quorum-counts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Cases []struct {
			Name       string `json:"name"`
			Threshold  int    `json:"threshold"`
			N          int    `json:"n"`
			Signatures string `json:"signatures"`
			Decision   string `json:"decision"`
			Count      int    `json:"count"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixtures.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var signatures []*OrganVerdict
			if c.Signatures == "all" {
				signatures = source.Cases[0].Signatures
			}
			result := Tally(source.ActionHash, signatures, source.Pubkeys, c.Threshold, c.N)
			if result.Decision != c.Decision || result.ConsensusCount != c.Count {
				t.Fatalf("got %s count %d, want %s count %d", result.Decision, result.ConsensusCount, c.Decision, c.Count)
			}
			if c.Signatures == "all" && c.Decision == "rejected" && len(result.Checks) != 0 {
				t.Fatal("invalid quorum performed signature checks")
			}
		})
	}
}
