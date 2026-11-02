package worker

import "encoding/json"

// TeamObjectsSourceScopeSHA256 binds the ORIGINAL object-only Teams source
// prefix delegation without inventing future inventory keys. Actual capture
// still validates every independently observed Team object against these exact
// prefixes through FormalSourceScopeSHA256/OpenFormalCaptureSources.
func TeamObjectsSourceScopeSHA256(m FormalSourceMount) (string, error) {
	if m.Redis != nil || m.RedisScope != nil || m.Objects == nil || len(m.RedisPrefixes) != 0 || len(m.RedisExcludedPrefixes) != 0 || !validObjectSourcePrefixes(m.ObjectPrefixes) {
		return "", ErrRequest
	}
	raw, err := json.Marshal(struct {
		Operation                    string
		RedisScope                   *RedisSourceBoundary
		ObjectPrefixes               []ObjectSourcePrefix
		RedisMapping, ObjectsMapping *SourceTLSMapping
	}{"capture-team-objects", nil, m.ObjectPrefixes, nil, m.Objects})
	if err != nil {
		return "", ErrRequest
	}
	return sourceDigest(raw), nil
}
