package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantError error
	}{
		{
			name:      "no authorization header",
			headers:   http.Header{},
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - missing token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:   "Break on purpose",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name: "malformed header - wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name: "valid header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey:   "my-secret-key",
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("got key %q, want %q", gotKey, tt.wantKey)
			}

			if (gotErr != nil && tt.wantError == nil) ||
				(gotErr == nil && tt.wantError != nil) {
				t.Errorf("got err %v, want %v", gotErr, tt.wantError)
			}

			if gotErr != nil && tt.wantError != nil &&
				gotErr.Error() != tt.wantError.Error() {
				t.Errorf("got err %v, want %v", gotErr, tt.wantError)
			}
		})
	}
}
