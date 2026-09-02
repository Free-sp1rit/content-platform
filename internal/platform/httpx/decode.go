package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
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
	if err := validateExactObjectFields(raw, dst); err != nil {
		return invalidJSON(err)
	}

	objectDecoder := json.NewDecoder(bytes.NewReader(raw))
	objectDecoder.DisallowUnknownFields()
	if err := objectDecoder.Decode(dst); err != nil {
		return invalidJSON(err)
	}
	return nil
}

func validateExactObjectFields(raw json.RawMessage, dst any) error {
	allowed, err := exactJSONFields(dst)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("request body must be a JSON object")
	}
	seen := make(map[string]struct{}, len(allowed))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("request object field is invalid")
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("request object field is invalid")
		}
		if _, ok := allowed[name]; !ok {
			return errors.New("request object field is unknown")
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("request object field is duplicated")
		}
		seen[name] = struct{}{}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errors.New("request object field value is invalid")
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("request body must be a JSON object")
	}
	if err := decoder.Decode(&json.RawMessage{}); err != io.EOF {
		return errors.New("request body contains multiple JSON values")
	}
	return nil
}

func exactJSONFields(dst any) (map[string]struct{}, error) {
	value := reflect.ValueOf(dst)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() {
		return nil, errors.New("JSON destination must be a non-nil pointer to a struct")
	}
	typeOfDestination := value.Type().Elem()
	if typeOfDestination.Kind() != reflect.Struct {
		return nil, errors.New("JSON destination must point to a struct")
	}

	fields := make(map[string]struct{}, typeOfDestination.NumField())
	for index := 0; index < typeOfDestination.NumField(); index++ {
		field := typeOfDestination.Field(index)
		if field.PkgPath != "" {
			continue
		}
		if field.Anonymous {
			return nil, errors.New("embedded JSON destination fields are unsupported")
		}

		name := field.Name
		if tag, ok := field.Tag.Lookup("json"); ok {
			name, _, _ = strings.Cut(tag, ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, errors.New("JSON destination contains duplicate field names")
		}
		fields[name] = struct{}{}
	}
	return fields, nil
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
