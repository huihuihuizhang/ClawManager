package systembackup

import (
	"encoding/json"
	"sort"
	"strings"
)

type minioGateStatement struct {
	Sid      string   `json:"Sid,omitempty"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}
type minioGatePolicy struct {
	Version   string               `json:"Version"`
	Statement []minioGateStatement `json:"Statement"`
}

// Used by C's native installer and actual gate observation. These are requested
// policies only until authenticated self/native policy probes verify them.
func MinIOReadGatePolicies(buckets []string) (keeper, reader []byte, err error) {
	if len(buckets) == 0 || len(buckets) > 64 {
		return nil, nil, ErrMinIOReadGate
	}
	ba, oa := []string{}, []string{}
	seen := map[string]bool{}
	for _, b := range buckets {
		if b == "" || strings.ContainsAny(b, "/*?\\\x00\r\n:") || seen[b] {
			return nil, nil, ErrMinIOReadGate
		}
		seen[b] = true
		ba = append(ba, "arn:aws:s3:::"+b)
		oa = append(oa, "arn:aws:s3:::"+b+"/*")
	}
	sort.Strings(ba)
	sort.Strings(oa)
	common := minioGateStatement{Effect: "Allow", Action: []string{"s3:ListAllMyBuckets"}, Resource: []string{"*"}}
	k := minioGatePolicy{"2012-10-17", []minioGateStatement{{Effect: "Allow", Action: []string{"admin:*"}, Resource: []string{"*"}}, common, {Effect: "Allow", Action: []string{"s3:DeleteBucketPolicy", "s3:GetBucketLocation", "s3:GetBucketPolicy", "s3:GetBucketVersioning", "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration", "s3:ListBucket", "s3:PutBucketPolicy"}, Resource: ba}}}
	r := minioGatePolicy{"2012-10-17", []minioGateStatement{common, {Effect: "Allow", Action: []string{"s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:ListBucketVersions"}, Resource: ba}, {Effect: "Allow", Action: []string{"s3:GetObject", "s3:GetObjectTagging", "s3:GetObjectVersion", "s3:GetObjectVersionTagging", "s3:ListMultipartUploadParts"}, Resource: oa}}}
	keeper, _ = json.Marshal(k)
	// The actual historical census checks each fixed version's retention and
	// legal hold plus bucket object-lock state. These are read operations;
	// omitting them makes a valid historical source fail after writer fencing.
	r.Statement[1].Action = append(r.Statement[1].Action, "s3:GetBucketObjectLockConfiguration")
	r.Statement[2].Action = append(r.Statement[2].Action, "s3:GetObjectRetention", "s3:GetObjectLegalHold")
	for i := range r.Statement {
		sort.Strings(r.Statement[i].Action)
	}
	reader, _ = json.Marshal(r)
	return keeper, reader, nil
}
func minioGateNormalizedPolicy(raw []byte) (minioGatePolicy, bool) {
	var p minioGatePolicy
	if minioGateDecode(raw, &p) != nil || p.Version != "2012-10-17" || len(p.Statement) == 0 || len(p.Statement) > 64 {
		return p, false
	}
	for n := range p.Statement {
		s := &p.Statement[n]
		if s.Effect != "Allow" || len(s.Action) == 0 || len(s.Resource) == 0 {
			return p, false
		}
		s.Sid = ""
		sort.Strings(s.Action)
		sort.Strings(s.Resource)
	}
	sort.Slice(p.Statement, func(a, b int) bool { return minioGateHash(p.Statement[a]) < minioGateHash(p.Statement[b]) })
	return p, true
}
func minioGateSamePolicy(a, b []byte) bool {
	x, ok := minioGateNormalizedPolicy(a)
	if !ok {
		return false
	}
	y, ok := minioGateNormalizedPolicy(b)
	return ok && minioGateHash(x) == minioGateHash(y)
}
func minioGateOutputPolicy(raw []byte, business []string) bool {
	p, ok := minioGateNormalizedPolicy(raw)
	if !ok {
		return false
	}
	source := map[string]bool{}
	for _, b := range business {
		source[b] = true
	}
	read := map[string]bool{}
	for _, a := range []string{"s3:GetBucketObjectLockConfiguration", "s3:GetObjectRetention", "s3:GetObjectLegalHold"} {
		read[a] = true
	}
	for _, a := range []string{"admin:GetUser", "admin:GetPolicy", "admin:ServerInfo"} {
		read[a] = true
	}
	for _, a := range []string{"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:GetObjectVersionTagging", "s3:ListAllMyBuckets", "s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts", "s3:GetBucketLocation", "s3:GetBucketVersioning"} {
		read[a] = true
	}
	write := map[string]bool{}
	for _, a := range []string{"s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload"} {
		write[a] = true
	}
	for _, s := range p.Statement {
		mutates := false
		for _, a := range s.Action {
			if write[a] {
				mutates = true
			} else if !read[a] {
				return false
			}
		}
		if !mutates {
			continue
		}
		for _, r := range s.Resource {
			if !strings.HasPrefix(r, "arn:aws:s3:::") {
				return false
			}
			name := strings.SplitN(strings.TrimPrefix(r, "arn:aws:s3:::"), "/", 2)[0]
			if name == "" || strings.ContainsAny(name, "*?\\:") || source[name] {
				return false
			}
		}
	}
	return true
}
