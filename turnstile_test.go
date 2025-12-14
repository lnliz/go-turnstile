package turnstile

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerify_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := TurnstileResponse{
			Success:     true,
			ChallengeTS: time.Now(),
			Hostname:    "example.com",
			Action:      "login",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	verifier := NewTurnstileVerifier("test-secret")
	verifier.endpoint = server.URL

	result, err := verifier.Verify("test-token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Success {
		t.Error("expected success to be true")
	}
}

func TestVerify_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := TurnstileResponse{
			Success:    false,
			ErrorCodes: []string{"invalid-token"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	verifier := NewTurnstileVerifier("test-secret")
	verifier.endpoint = server.URL

	result, err := verifier.Verify("invalid-token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Success {
		t.Error("expected success to be false")
	}
	if len(result.ErrorCodes) == 0 {
		t.Error("expected error codes")
	}
}

func TestVerify_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	verifier := NewTurnstileVerifier("test-secret")
	verifier.endpoint = server.URL

	_, err := verifier.Verify("test-token")
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestVerify_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	verifier := NewTurnstileVerifier("test-secret")
	verifier.endpoint = server.URL

	_, err := verifier.Verify("test-token")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestVerify_NetworkError(t *testing.T) {
	verifier := NewTurnstileVerifier("test-secret")
	verifier.endpoint = "http://localhost:1"

	_, err := verifier.Verify("test-token")
	if err == nil {
		t.Error("expected network error")
	}
}

func TestVerify_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	verifier := NewTurnstileVerifier("test-secret")
	verifier.endpoint = server.URL

	_, err := verifier.Verify("test-token")
	if err == nil {
		t.Error("expected error for empty response")
	}
}

func TestVerify_JSONEncodeError(t *testing.T) {
	verifier := NewTurnstileVerifier("test-secret")
	verifier.extraData = make(chan int)

	_, err := verifier.Verify("test-token")
	if err == nil {
		t.Error("expected JSON encoding error")
	}
}
