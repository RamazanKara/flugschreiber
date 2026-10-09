package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

func fileError(path string, data []byte, offset int64, err error) error {
	prefix := data[:offset]
	line := bytes.Count(prefix, []byte{'\n'}) + 1
	column := len(prefix) - bytes.LastIndexByte(prefix, '\n')
	return fmt.Errorf("config: parse %s:%d:%d: %w", path, line, column, err)
}

func nextJSONByte(data []byte, offset int64) int64 {
	for offset < int64(len(data)) && strings.ContainsRune(" \r\n\t,:", rune(data[offset])) {
		offset++
	}
	return offset
}

func configError(data []byte) (int64, error) {
	return valueError(data, reflect.TypeFor[Config]())
}

// The JSON decoder supplies offsets for syntax errors, but not unknown fields
// or errors from Duration.UnmarshalJSON. Walk only a rejected document to find
// the field without changing the decoder's merging or compatibility rules.
func valueError(data []byte, typ reflect.Type) (int64, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err := dec.Decode(reflect.New(typ).Interface())
	if err == nil {
		return -1, nil
	}
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		return syntax.Offset - 1, err
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return int64(len(data)), err
	}
	start := nextJSONByte(data, 0)
	if (typ.Kind() != reflect.Struct || data[start] != '{') &&
		(typ.Kind() != reflect.Slice || data[start] != '[') {
		return start, err
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	_, _ = dec.Token()
	for dec.More() {
		offset := nextJSONByte(data, dec.InputOffset())
		var child reflect.Type
		if typ.Kind() == reflect.Struct {
			key, _ := dec.Token()
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
				if strings.EqualFold(name, key.(string)) {
					child = field.Type
					break
				}
			}
			if child == nil {
				return offset, fmt.Errorf("json: unknown field %q", key)
			}
			offset = nextJSONByte(data, dec.InputOffset())
		} else {
			child = typ.Elem()
		}
		var raw json.RawMessage
		_ = dec.Decode(&raw)
		if nested, detail := valueError(raw, child); detail != nil {
			return offset + nested, detail
		}
	}
	return start, err
}
