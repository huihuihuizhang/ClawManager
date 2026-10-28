package systembackupread

import "context"

type ConfigResourceListDTO struct {
	Items       []ConfigResourceDTO `json:"items"`
	NextCursor  *string             `json:"next_cursor"`
	Consistency string              `json:"consistency"`
}

func ProjectConfigList(page ConfigPage, nextCursor string, limit int) (ConfigResourceListDTO, error) {
	if limit < 1 || limit > 500 || !installationID.MatchString(page.InstallationID) ||
		len(page.Items) > limit || page.HasMore != (nextCursor != "") ||
		page.HasMore && (len(page.Items) != limit || page.BeforeVersion == 0) ||
		len(page.Items) == 0 && page.HasMore ||
		page.CutoffVersion > maxJSONSafeInteger {
		return ConfigResourceListDTO{}, ErrUnavailable
	}
	if len(page.Items) != 0 && (page.CutoffVersion == 0 || page.Items[0].version > page.CutoffVersion) {
		return ConfigResourceListDTO{}, ErrUnavailable
	}
	result := ConfigResourceListDTO{Items: make([]ConfigResourceDTO, 0, len(page.Items)), Consistency: "stable_cutoff"}
	if nextCursor != "" {
		result.NextCursor = &nextCursor
	}
	for i, row := range page.Items {
		if row.installationID != page.InstallationID || row.version == 0 || row.version > page.CutoffVersion ||
			i > 0 && row.version >= page.Items[i-1].version {
			return ConfigResourceListDTO{}, ErrUnavailable
		}
		dto, err := ProjectConfigResource(row)
		if err != nil {
			return ConfigResourceListDTO{}, ErrUnavailable
		}
		result.Items = append(result.Items, dto)
	}
	if page.HasMore && page.Items[len(page.Items)-1].version != page.BeforeVersion {
		return ConfigResourceListDTO{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) ListConfigDTO(ctx context.Context, limit int, token string) (ConfigResourceListDTO, error) {
	if s == nil || s.reader == nil || s.cursor == nil {
		return ConfigResourceListDTO{}, ErrDenied
	}
	request := ConfigPageRequest{Limit: limit}
	if token != "" {
		var err error
		request, err = s.cursor.DecodeConfig(token, limit)
		if err != nil {
			return ConfigResourceListDTO{}, err
		}
	}
	page, err := s.reader.ListConfigVersions(ctx, request)
	if err != nil {
		return ConfigResourceListDTO{}, err
	}
	var next string
	if page.HasMore {
		next, err = s.cursor.EncodeConfig(request, page)
		if err != nil {
			return ConfigResourceListDTO{}, ErrUnavailable
		}
	}
	return ProjectConfigList(page, next, limit)
}
