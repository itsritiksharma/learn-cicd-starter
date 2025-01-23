package auth
import (
	"errors"
	"net/http"
  "testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedKey    string
		expectedErr    error
	}{
		{
			name:           "No Authorization Header",
			headers:        http.Header{},
			expectedKey:    "",
			expectedErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name:           "Malformed Authorization Header (no space)",
			headers:        http.Header{"Authorization": []string{"ApiKey12345"}},
			expectedKey:    "",
			expectedErr:    errors.New("malformed authorization header"),
		},
		{
			name:           "Malformed Authorization Header (wrong scheme)",
			headers:        http.Header{"Authorization": []string{"Bearer 12345"}},
			expectedKey:    "",
			expectedErr:    errors.New("malformed authorization header"),
		},
		{
			name:           "Correct Authorization Header",
			headers:        http.Header{"Authorization": []string{"ApiKey 12345"}},
			expectedKey:    "12345",
			expectedErr:    nil,
		},
		{
			name:           "Empty API Key",
			headers:        http.Header{"Authorization": []string{"ApiKey "}},
			expectedKey:    "",
			expectedErr:    errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualKey, actualErr := GetAPIKey(tt.headers)
			if actualKey != tt.expectedKey {
				t.Errorf("Expected API Key: %v, got: %v", tt.expectedKey, actualKey)
			}
			if (actualErr != nil) && (tt.expectedErr == nil || actualErr.Error() != tt.expectedErr.Error()) {
				t.Errorf("Expected error: %v, got: %v", tt.expectedErr, actualErr)
			}
			if actualErr == nil && tt.expectedErr != nil {
				t.Errorf("Expected error: %v, got: nil", tt.expectedErr)
			}
		})
	}
}
