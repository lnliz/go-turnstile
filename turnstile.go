package turnstile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type TurnstileResponse struct {
	Success     bool      `json:"success"`
	ErrorCodes  []string  `json:"error-codes"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	Action      string    `json:"action"`
	ClientData  string    `json:"cdata"`
}

const (
	endpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
)

type TurnstileVerifier struct {
	secret     string
	endpoint   string
	HttpClient *http.Client
	extraData  interface{}
}

func NewTurnstileVerifier(secret string) *TurnstileVerifier {
	return &TurnstileVerifier{
		HttpClient: http.DefaultClient,
		secret:     secret,
		endpoint:   endpoint,
	}
}

func (v *TurnstileVerifier) Verify(token string) (*TurnstileResponse, error) {
	p := struct {
		SecretKey     string      `json:"secret"`
		ResponseToken string      `json:"response"`
		Extra         interface{} `json:"extra,omitempty"`
	}{
		v.secret,
		token,
		v.extraData,
	}

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(p); err != nil {
		return nil, err
	}
	res, err := v.HttpClient.Post(v.endpoint, "application/json", &b)
	if err != nil {
		return nil, fmt.Errorf("error POST: %w", err)
	}
	defer res.Body.Close()
	r := &TurnstileResponse{}
	if err := json.NewDecoder(res.Body).Decode(r); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}
	return r, nil
}
