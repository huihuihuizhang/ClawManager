package systembackupreferenceprobe

import (
	"encoding/json"
)

const minioEffectiveOwnerGuardPath = "/minio/admin/v3/help-config-kv"

func minioEffectiveAdminAccessDenied(raw []byte) error {
	if len(raw) == 0 || len(raw) > 8192 || minioPermissionUniqueJSON(raw) != nil {
		return minioPermissionFailure("effective-discriminator-response")
	}
	var fields map[string]string
	if json.Unmarshal(raw, &fields) != nil {
		return minioPermissionFailure("effective-discriminator-json")
	}
	allowed := map[string]bool{"Code": true, "Message": true, "Key": true, "BucketName": true, "Resource": true, "Region": true, "RequestId": true, "HostId": true, "ActualObjectSize": true, "RangeRequested": true}
	for key := range fields {
		if !allowed[key] {
			return minioPermissionFailure("effective-discriminator-unknown-field")
		}
	}
	if fields["Code"] != "AccessDenied" || fields["Message"] == "" || fields["Resource"] != minioEffectiveOwnerGuardPath || fields["RequestId"] == "" || fields["HostId"] == "" || fields["BucketName"] != "" || fields["Key"] != "" {
		return minioPermissionFailure("effective-discriminator-not-access-denied")
	}
	return nil
}
