package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/Free-sp1rit/content-platform/internal/platform/apperror"
)

func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	contentType, ok := singleHeaderValue(r.Header, "Content-Type")
	if !ok {
		return invalidJSON(errors.New("exactly one content type is required"))
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return invalidJSON(errors.New("content type is not application/json"))
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	var raw json.RawMessage

	if err := decoder.Decode(&raw); err != nil {
		return invalidJSON(err)
	}
	if err := decoder.Decode(&json.RawMessage{}); err != io.EOF {
		return invalidJSON(err)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return invalidJSON(errors.New("request body must be a JSON object"))
	}

	objectDecoder := json.NewDecoder(bytes.NewReader(raw))
	objectDecoder.DisallowUnknownFields()
	if err := objectDecoder.Decode(dst); err != nil {
		return invalidJSON(err)
	}
	return nil
}

func invalidJSON(cause error) error {
	return apperror.Wrap(
		apperror.InvalidArgument,
		"invalid_request",
		"request body is invalid",
		cause,
	)
}

func singleHeaderValue(header http.Header, wanted string) (string, bool) {
	var value string
	count := 0
	for name, values := range header {
		if !strings.EqualFold(name, wanted) {
			continue
		}
		for _, candidate := range values {
			count++
			value = candidate
		}
	}
	return value, count == 1
}
