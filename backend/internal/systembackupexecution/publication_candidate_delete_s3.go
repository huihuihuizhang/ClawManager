package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7/pkg/signer"
)

func originalCandidateDeleteObject(target PublicationTargetMaterials, backup string, attempt uint64, object ArtifactReadObject) bool {
	if target.validate() != nil || target.RemoteStagingRoot == "" || !strings.HasPrefix(backup, "sbk_") || len(backup) != 40 || attempt != 1 {
		return false
	}
	if _, err := uuid.Parse(strings.TrimPrefix(backup, "sbk_")); err != nil {
		return false
	}
	return object.Key == target.RemoteStagingRoot+backup+"/"+strconv.FormatUint(attempt, 10)+"/manifest-candidate.json" && object.Version != "" && object.Version != "null" && object.Version != "latest" && object.Version != "current" && len(object.Version) <= 256 && !strings.ContainsAny(object.Version, "\x00\r\n") && object.Size > 0 && object.Size <= 262144 && formalCandidateDigest(object.SHA256)
}

func (s *nativePublicationS3) candidateReadTransport(backup string, attempt uint64, object ArtifactReadObject) (*nativePublicationS3, error) {
	if s == nil || s.client == nil || !originalCandidateDeleteObject(s.config, backup, attempt, object) {
		return nil, errPublicationUnavailable
	}
	copy := *s
	copy.config.Root = s.config.RemoteStagingRoot
	copy.config.RemoteStagingRoot = ""
	copy.readOnly = true
	copy.maxObjectBytes = 262144
	return &copy, nil
}

// Transport only: callers must first commit the exact original104 deleting
// intent. No read/write credential or presigned PUT may authorize this request.
// This function never interprets a DELETE acknowledgement as cleanup success.
func (s *nativePublicationS3) deleteFixedPublicationCandidateVersion(ctx context.Context, backup string, attempt uint64, object ArtifactReadObject, deadline time.Time) error {
	if s == nil || s.client == nil || s.readOnly || ctx == nil || ctx.Err() != nil || !originalCandidateDeleteObject(s.config, backup, attempt, object) || s.config.DeleteIdentityHash == "" || deadline.IsZero() {
		return errPublicationUnavailable
	}
	credential, err := loadNativePublicationCredential(s.config.DeleteCredentialFile, s.config.DeleteCredentialSHA256)
	if err != nil {
		return errPublicationUnavailable
	}
	if credential.Until.Before(deadline) {
		deadline = credential.Until
	}
	seconds := int64(time.Until(deadline) / time.Second)
	if seconds < 1 || seconds > 86400 {
		return errPublicationUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	u, err := url.Parse(s.config.Endpoint)
	if err != nil {
		return errPublicationUnavailable
	}
	u.Path = "/" + s.config.Bucket + "/" + object.Key
	query := u.Query()
	query.Set("versionId", object.Version)
	u.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return errPublicationUnavailable
	}
	request.Header.Set("X-Amz-Content-Sha256", hash(nil))
	request = signer.PreSignV4(*request, credential.AccessKey, credential.SecretKey, credential.SessionToken, s.config.Region, seconds)
	response, err := s.client.Do(request)
	if err != nil {
		return errPublicationUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(body) != 0 || response.StatusCode != http.StatusNoContent || response.Header.Get("x-amz-version-id") != object.Version || response.Header.Get("x-amz-delete-marker") == "true" {
		return errPublicationUnavailable
	}
	return nil
}

// An authenticated fixed-version GET must return an explicit NoSuchVersion.
// Generic 404, NoSuchKey, denied, redirects and malformed/truncated XML remain
// unknown. Checking the latest key could hide a retained old version.
func (s *nativePublicationS3) publicationCandidateVersionAbsent(ctx context.Context, backup string, attempt uint64, object ArtifactReadObject, deadline time.Time) error {
	reader, err := s.candidateReadTransport(backup, attempt, object)
	if err != nil {
		return err
	}
	response, err := reader.request(ctx, http.MethodGet, object.Key, object.Version, nil, 0, "", deadline, false, "")
	if err != nil {
		return errPublicationUnavailable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(raw) == 0 || len(raw) > 8192 || response.StatusCode != http.StatusNotFound || response.Header.Get("Content-Encoding") != "" {
		return errPublicationUnavailable
	}
	if !originalCandidateAbsenceBody(raw, object) {
		return errPublicationUnavailable
	}
	return nil
}

func originalCandidateAbsenceBody(raw []byte, object ArtifactReadObject) bool {
	if len(raw) == 0 || len(raw) > 8192 {
		return false
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	fields := map[string]string{}
	opened, closed := false, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
		switch value := token.(type) {
		case xml.StartElement:
			if closed || value.Name.Space != "" || len(value.Attr) != 0 {
				return false
			}
			if !opened {
				if value.Name.Local != "Error" {
					return false
				}
				opened = true
				continue
			}
			switch value.Name.Local {
			case "Code", "Key", "VersionId", "Message", "RequestId", "HostId", "Resource":
			default:
				return false
			}
			if _, seen := fields[value.Name.Local]; seen {
				return false
			}
			var body strings.Builder
			fieldClosed := false
			for !fieldClosed {
				part, err := decoder.Token()
				if err != nil {
					return false
				}
				switch field := part.(type) {
				case xml.CharData:
					body.Write(field)
				case xml.EndElement:
					if field.Name != value.Name {
						return false
					}
					fieldClosed = true
				default:
					return false
				}
			}
			fields[value.Name.Local] = body.String()
		case xml.EndElement:
			if !opened || closed || value.Name.Space != "" || value.Name.Local != "Error" {
				return false
			}
			closed = true
		case xml.CharData:
			if len(bytes.TrimSpace(value)) != 0 {
				return false
			}
		case xml.ProcInst:
			if opened || value.Target != "xml" {
				return false
			}
		default:
			return false
		}
	}
	return opened && closed && fields["Code"] == "NoSuchVersion" && (fields["Key"] == "" || fields["Key"] == object.Key) && (fields["VersionId"] == "" || fields["VersionId"] == object.Version)
}
