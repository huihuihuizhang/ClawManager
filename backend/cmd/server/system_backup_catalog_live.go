package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupread"
	"github.com/gin-gonic/gin"
)

func loadPublicationHTTPRead(getenv func(string) string) (*systembackupexecution.PublicationHTTPReader, error) {
	path, sha := getenv("SYSTEM_BACKUP_PUBLICATION_READ_FILE"), getenv("SYSTEM_BACKUP_PUBLICATION_READ_SHA256")
	if path == "" && sha == "" {
		return nil, nil
	}
	return systembackupexecution.NewPublicationHTTPReader(context.Background(), systembackupexecution.PublicationHTTPReadInput{File: path, SHA256: sha})
}

func (l *liveBackupRead) publicationReader(c *gin.Context) (*systembackupread.Reader, context.Context, bool) {
	c.Header("X-Content-Type-Options", "nosniff")
	if l == nil || l.authorizer == nil || l.db == nil {
		liveReadError(c, systembackupread.ErrUnavailable)
		return nil, nil, false
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	scope, e := l.authorizer.Scope(c.Request)
	if e != nil {
		liveReadError(c, e)
		return nil, nil, false
	}
	reader, e := systembackupread.NewReader(l.db, scope)
	if e != nil {
		liveReadError(c, e)
		return nil, nil, false
	}
	return reader, scope.Context(), true
}

// Signed records already have canonical JSON bytes. Disable HTML escaping so
// embedding the RawMessage does not rewrite their signed/hash-bound strings.
func writePublicationReadJSON(c *gin.Context, result any) {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(result) != nil {
		liveReadError(c, systembackupread.ErrUnavailable)
		return
	}
	c.Header("X-System-Backup-Data-Source", "live")
	c.Data(http.StatusOK, "application/json", body.Bytes())
}

func (l *liveBackupRead) listCatalogRecords(c *gin.Context) {
	c.Header("X-Content-Type-Options", "nosniff")
	limit, token, _, e := liveReadListQuery(c, false)
	if e != nil {
		liveReadError(c, e)
		return
	}
	reader, ctx, ok := l.publicationReader(c)
	if !ok {
		return
	}
	if l.publication == nil {
		liveReadError(c, systembackupread.ErrUnavailable)
		return
	}
	codec, e := systembackupread.NewCatalogCursorCodec(l.cursorKey)
	if e != nil {
		liveReadError(c, e)
		return
	}
	result, e := reader.ListCatalogRecordsCurrentV1(ctx, limit, token, codec, l.publication)
	if e != nil {
		liveReadError(c, e)
		return
	}
	writePublicationReadJSON(c, result)
}

func (l *liveBackupRead) getCatalogRecord(c *gin.Context) {
	c.Header("X-Content-Type-Options", "nosniff")
	if c.Request.URL.RawQuery != "" {
		liveReadError(c, systembackupread.ErrInvalid)
		return
	}
	reader, ctx, ok := l.publicationReader(c)
	if !ok {
		return
	}
	if l.publication == nil {
		liveReadError(c, systembackupread.ErrUnavailable)
		return
	}
	result, e := reader.ReadCatalogRecordCurrentV1(ctx, c.Param("id"), l.publication)
	if e != nil {
		liveReadError(c, e)
		return
	}
	writePublicationReadJSON(c, result)
}

func (l *liveBackupRead) getBackupManifest(c *gin.Context) {
	c.Header("X-Content-Type-Options", "nosniff")
	if c.Request.URL.RawQuery != "" {
		liveReadError(c, systembackupread.ErrInvalid)
		return
	}
	reader, ctx, ok := l.publicationReader(c)
	if !ok {
		return
	}
	if l.publication == nil {
		liveReadError(c, systembackupread.ErrUnavailable)
		return
	}
	raw, e := reader.ReadBackupManifestCurrentV1(ctx, c.Param("id"), l.publication, l.publication)
	if e != nil {
		liveReadError(c, e)
		return
	}
	c.Header("X-System-Backup-Data-Source", "live")
	c.Data(http.StatusOK, "application/json", raw)
}
