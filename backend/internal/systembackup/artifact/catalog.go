package artifact

import (
	"context"
	"io"
	"sort"
	"strings"
)

// DomainContract is signed together with the bundle. It describes a portable
// domain contribution, not a six-domain disaster-recovery qualification.
// Other owners can compose these contributions without trusting display labels.
type DomainContract struct {
	Version         string            `json:"version"`
	PolicySHA256    string            `json:"policy_sha256"`
	RuntimePolicies map[string]string `json:"runtime_policies"` // instance part -> exact rule digest
	Dependencies    []string          `json:"dependencies"`
	Assets          bool              `json:"assets"`
}

func (c *DomainContract) valid(instances int) bool {
	if c == nil || !digest(c.PolicySHA256) || len(c.RuntimePolicies) != instances {
		return false
	}
	if c.Version == "users-instances-contribution.v1" {
		if len(c.Dependencies) != 3 {
			return false
		}
	} else if c.Version == "users-instances-contribution.v2" {
		if len(c.Dependencies) != 4 || c.Dependencies[3] != "resources" {
			return false
		}
	} else {
		return false
	}
	for id, hash := range c.RuntimePolicies {
		if !instancePart.MatchString(id) || !digest(hash) {
			return false
		}
	}
	return c.Dependencies[0] == "ai_gateway" && c.Dependencies[1] == "skill_hub" && c.Dependencies[2] == "teams"
}
func digest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type CatalogEntry struct {
	ID               string          `json:"id"`
	PolicyVersion    string          `json:"policy_version"`
	Contract         *DomainContract `json:"contract,omitempty"`
	Users, Instances int
}
type CatalogPage struct {
	Entries []CatalogEntry
	Next    string
}

// Scan is a bounded, resumable, source-independent catalog reader. Every entry
// is reauthenticated including every ciphertext object. Uncommitted indexes do
// not appear; corrupt committed objects stop the scan, never silently disappear.
func (d Directory) Scan(ctx context.Context, after string, limit int) (CatalogPage, error) {
	if limit < 1 || limit > 100 || after != "" && !name.MatchString(after) || d.Root == nil {
		return CatalogPage{}, ErrArtifact
	}
	f, e := d.Root.Open(".")
	if e != nil {
		return CatalogPage{}, ErrArtifact
	}
	defer f.Close()
	var ids []string
	for {
		entries, e := f.ReadDir(256)
		for _, entry := range entries {
			if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".committed") {
				id := strings.TrimSuffix(entry.Name(), ".committed")
				if !name.MatchString(id) {
					return CatalogPage{}, ErrArtifact
				}
				if id > after {
					ids = append(ids, id)
				}
			}
		}
		if len(ids) > 100000 {
			return CatalogPage{}, ErrArtifact
		}
		if e != nil {
			if e != io.EOF {
				return CatalogPage{}, ErrArtifact
			}
			break
		}
		if ctx.Err() != nil {
			return CatalogPage{}, ctx.Err()
		}
	}
	sort.Strings(ids)
	page := CatalogPage{}
	for i, id := range ids {
		if i == limit {
			page.Next = ids[i-1]
			break
		}
		b, e := d.Read(ctx, id)
		if e != nil {
			return CatalogPage{}, e
		}
		page.Entries = append(page.Entries, CatalogEntry{ID: b.ID, PolicyVersion: b.PolicyVersion, Contract: b.Contract, Users: b.Users, Instances: b.Instances})
	}
	return page, nil
}
