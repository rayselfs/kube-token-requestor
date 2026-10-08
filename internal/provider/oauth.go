package provider

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/safejson"
	"k8s.io/client-go/kubernetes"
)

const tokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
const accessToken = "urn:ietf:params:oauth:token-type:access_token"

// Subject reads only an explicitly mounted projected token, freshly on every exchange.
type OAuthTokenExchange struct {
	Management kubernetes.Interface
	Subject    func(volume string) ([]byte, error)
	Now        func() time.Time
}

func (p OAuthTokenExchange) Acquire(ctx context.Context, c config.Cluster) (IssuerCredential, error) {
	var result IssuerCredential
	settings := c.Provider
	if settings.Type != "OAuthTokenExchange" || settings.TrustSecret == nil || settings.ClientSecret == nil {
		return result, Trust
	}
	trust, err := ReadSecret(ctx, p.Management, *settings.TrustSecret, "ca.crt", "api-ca.crt")
	if err != nil {
		return result, err
	}
	if credential.Hash(trust.Data["api-ca.crt"]) != c.CASHA256 {
		return result, Trust
	}
	if _, err := HTTP(trust.Data["api-ca.crt"]); err != nil {
		return result, err
	}
	client, err := HTTP(trust.Data["ca.crt"])
	if err != nil {
		return result, err
	}
	defer client.CloseIdleConnections()
	secret, err := ReadSecret(ctx, p.Management, *settings.ClientSecret, "client-secret")
	if err != nil {
		return result, err
	}
	subject, err := p.Subject(settings.SubjectTokenVolume)
	if err != nil {
		return result, Auth
	}
	claims, err := credential.Parse(string(subject))
	now := p.Now()
	if err != nil || claims.Expires <= now.Add(60*time.Second).Unix() || claims.Issued > now.Add(60*time.Second).Unix() || claims.NotBefore > now.Add(60*time.Second).Unix() ||
		!strings.HasPrefix(claims.Subject, "system:serviceaccount:") || !credential.SameSet(claims.Audience, []string{settings.SubjectTokenAudience}) {
		return result, Auth
	}
	form := url.Values{"grant_type": {tokenExchange}, "subject_token": {string(subject)}, "subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"}, "requested_token_type": {accessToken}, "audience": {settings.Audience}, "scope": {strings.Join(settings.Scopes, " ")}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return result, Trust
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(settings.ClientID), url.QueryEscape(string(secret.Data["client-secret"])))
	response, err := client.Do(req)
	if err != nil {
		return result, Classify(err)
	}
	defer response.Body.Close()
	if response.StatusCode == 429 {
		seconds, err := strconv.Atoi(response.Header.Get("Retry-After"))
		after := 5 * time.Second
		if err == nil && seconds > 0 {
			after = min(time.Duration(seconds)*time.Second, 5*time.Minute)
		} else if date, err := http.ParseTime(response.Header.Get("Retry-After")); err == nil && date.After(p.Now()) {
			after = min(date.Sub(p.Now()), 5*time.Minute)
		}
		return result, &Retry{After: after}
	}
	if response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 400 {
		return result, Auth
	}
	if response.StatusCode != http.StatusOK {
		return result, Transport
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return result, Transport
	}
	var value struct {
		AccessToken     string `json:"access_token"`
		TokenType       string `json:"token_type"`
		IssuedTokenType string `json:"issued_token_type"`
		ExpiresIn       int64  `json:"expires_in"`
		Scope           string `json:"scope"`
		RefreshToken    string `json:"refresh_token"`
	}
	if safejson.Decode(body, &value, 65536) != nil || !strings.EqualFold(value.TokenType, "Bearer") || value.IssuedTokenType != accessToken || value.RefreshToken != "" ||
		value.ExpiresIn < settings.AcceptedMinSeconds || value.ExpiresIn > settings.AcceptedMaxSeconds || !credential.SameSet(strings.Fields(value.Scope), settings.Scopes) {
		return result, Auth
	}
	claims, err = credential.Parse(value.AccessToken)
	if err != nil || claims.Subject == "" || !credential.SameSet(claims.Audience, []string{settings.Audience}) || claims.Lifetime(now, 60*time.Second, settings.AcceptedMinSeconds, settings.AcceptedMaxSeconds) != nil ||
		claims.Expires < now.Add(time.Duration(value.ExpiresIn-60)*time.Second).Unix() || claims.Expires > now.Add(time.Duration(value.ExpiresIn+60)*time.Second).Unix() {
		return result, Auth
	}
	result.Bearer, result.CA, result.Expires = value.AccessToken, append([]byte(nil), trust.Data["api-ca.crt"]...), time.Unix(claims.Expires, 0)
	return result, nil
}
