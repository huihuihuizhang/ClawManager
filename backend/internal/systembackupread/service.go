package systembackupread

import (
	"context"
	"database/sql"
)

// ListResult is an internal authorized read plus an opaque continuation. A
// reviewed redacted DTO mapper must create the public API response.
type ListResult struct {
	Page       TaskPage
	NextCursor string
}

func (ListResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type Service struct {
	reader *Reader
	cursor *CursorCodec
}

func NewService(db *sql.DB, scope ScopeProvider, cursorKey []byte) (*Service, error) {
	reader, err := NewReader(db, scope)
	if err != nil {
		return nil, err
	}
	cursor, err := NewCursorCodec(cursorKey)
	if err != nil {
		return nil, err
	}
	return &Service{reader: reader, cursor: cursor}, nil
}

func (s *Service) ListTasks(ctx context.Context, kind TaskKind, status string, limit int, token string) (ListResult, error) {
	if s == nil || s.reader == nil || s.cursor == nil {
		return ListResult{}, ErrDenied
	}
	request := PageRequest{Kind: kind, Status: status, Limit: limit}
	if token != "" {
		var err error
		request, err = s.cursor.Decode(token, kind, status, limit)
		if err != nil {
			return ListResult{}, err
		}
	}
	page, err := s.reader.ListTasks(ctx, request)
	if err != nil {
		return ListResult{}, err
	}
	result := ListResult{Page: page}
	if page.HasMore {
		result.NextCursor, err = s.cursor.Encode(request, page)
		if err != nil {
			return ListResult{}, ErrUnavailable
		}
	}
	return result, nil
}

// ListTaskDTO is the only serializable task-list result from this service.
// HTTP registration still requires a production ScopeProvider and reviewed
// error/transport handling.
func (s *Service) ListTaskDTO(ctx context.Context, kind TaskKind, status string, limit int, token string) (TaskListDTO, error) {
	result, err := s.ListTasks(ctx, kind, status, limit, token)
	if err != nil {
		return TaskListDTO{}, err
	}
	return ProjectTaskList(result)
}
