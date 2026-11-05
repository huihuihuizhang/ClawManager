package install

import (
	"bytes"
	backup "clawreef/internal/systembackup"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestOriginalGatewayImageSQLMetadataNeverSerializesPrivateKey(t *testing.T) {
	key := bytes.Repeat([]byte("S"), 32)
	row := originalGatewayImageSQLRow{ID: "img_" + strings.Repeat("a", 32), KeySHA256: hash(key), key: key}
	raw, e := canonical(row)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, key) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(key))) || !bytes.Contains(raw, []byte(row.KeySHA256)) {
		t.Fatal("private image key leaked or exact key commitment omitted")
	}
	before := originalObjectSHA(row)
	clearOriginalGatewayImageKeys([]originalGatewayImageSQLRow{row})
	if before != originalObjectSHA(row) {
		t.Fatal("wiping private key changed committed SQL metadata")
	}
	for _, b := range key {
		if b != 0 {
			t.Fatal("private original image key not wiped")
		}
	}
}

// SQL/native mapping MODEL only; native AEAD correspondence still requires
// Root's real fixed-version MinIO TLS/GET/EOF test before qualification.
func TestOriginalGatewayImageHistoryRequiresExactNativeAndSQLKeyOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	row := originalGatewayImageSQLRow{ID: "img_" + strings.Repeat("a", 32), UserID: 1, ModelID: 3, KeySHA256: strings.Repeat("c", 64), ByteSize: 31}
	object := backup.OriginalProtectedMinIOObject{Bucket: "original-business", Key: "original-root/gateway-images/" + row.ID, VersionID: "actual-old-version", BodySHA256: strings.Repeat("b", 64), Size: 59}
	makeSource := func() *originalMinIOBusinessHistorySource {
		native := backup.OriginalGatewayImageVersionCorrespondence{ArtifactID: row.ID, SQLRowSHA256: originalObjectSHA(row), KeySHA256: row.KeySHA256, Bucket: object.Bucket, Key: object.Key, VersionID: object.VersionID, BodySHA256: object.BodySHA256, Size: object.Size}
		images := &originalPreColdSQLImageHistory{rows: []originalGatewayImageSQLRow{row}, rowsSHA256: originalObjectSHA([]originalGatewayImageSQLRow{row}), objects: []backup.OriginalGatewayImageVersionCorrespondence{native}}
		images.origin = images
		s := &originalMinIOBusinessHistorySource{ctx: ctx, prep: &PreparedOriginalAdoptionSQLCut{}, hold: &OriginalWriterHold{set: &PreparedOriginalWriterSet{owner: &OriginalWriterMaintenance{}}}, bucket: object.Bucket, prefix: "original-root/", rows: []originalSkillArchiveRow{}, byKey: map[string][]originalSkillArchiveRow{}, until: time.Now().Add(time.Minute), revision: "SQL-native-model", images: images}
		s.origin = s
		s.rowsSHA256 = originalObjectSHA(s.rows)
		return s
	}
	t.Run("exact-old-version", func(t *testing.T) {
		if c, ok := makeSource().classifyNativeObject(ctx, object); !ok || c.Kind != "original_sql_gateway_image_actual_aead" {
			t.Fatal("exact native/SQL old version missing")
		}
	})
	t.Run("foreign-SQL-key", func(t *testing.T) {
		s := makeSource()
		s.images.rows[0].KeySHA256 = strings.Repeat("d", 64)
		if _, ok := s.classifyNativeObject(ctx, object); ok {
			t.Fatal("foreign actual SQL key accepted")
		}
	})
	t.Run("foreign-SQL-row", func(t *testing.T) {
		s := makeSource()
		s.images.rows[0].UserID = 7
		if _, ok := s.classifyNativeObject(ctx, object); ok {
			t.Fatal("changed SQL owner accepted")
		}
	})
	t.Run("ciphertext-drift", func(t *testing.T) {
		x := object
		x.BodySHA256 = strings.Repeat("e", 64)
		if _, ok := makeSource().classifyNativeObject(ctx, x); ok {
			t.Fatal("different historical ciphertext accepted")
		}
	})
	t.Run("orphan-same-prefix", func(t *testing.T) {
		x := object
		x.Key = "original-root/gateway-images/img_" + strings.Repeat("f", 32)
		if _, ok := makeSource().classifyNativeObject(ctx, x); ok {
			t.Fatal("prefix-only ownership accepted")
		}
	})
}
