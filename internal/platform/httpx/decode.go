package httpx

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Free-sp1rit/content-platform/internal/platform/apperror"
)

func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return invalidJSON(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return invalidJSON(err)
	}
	return nil
}

func invalidJSON(cause error) error {
	return apperror.Wrap(
		apperror.InvalidArgument,
		string(apperror.InvalidArgument),
		"request body is invalid",
		cause,
	)
}
