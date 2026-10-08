// Package config validates enrollment metadata. It never reads credentials or contacts a cluster.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

const MaxBytes = 1 << 20

var (
	ErrInvalid  = errors.New("invalid registry")
	namePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Registry struct {
	SchemaVersion int       `json:"schemaVersion"`
	ManagementUID string    `json:"managementUID"`
	Clusters      []Cluster `json:"clusters"`
}

type Cluster struct {
	ID                string     `json:"id"`
	Enabled           *bool      `json:"enabled"`
	Endpoint          string     `json:"endpoint"`
	KubeSystemUID     string     `json:"kubeSystemUID"`
	CASHA256          string     `json:"caSHA256"`
	IdentityNamespace string     `json:"identityNamespace"`
	Audiences         []string   `json:"audiences"`
	ExpectedIssuer    Principal  `json:"expectedIssuer"`
	Provider          Provider   `json:"provider"`
	Lifetime          Lifetime   `json:"lifetime"`
	Consumers         []Consumer `json:"consumers"`
}

type Principal struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type Ref struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

type ServiceAccount struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type Deployment struct {
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	UID         string `json:"uid"`
	ImageDigest string `json:"imageDigest"`
}

type Lifetime struct {
	RequestedSeconds   int64 `json:"requestedSeconds"`
	AcceptedMinSeconds int64 `json:"acceptedMinSeconds"`
	AcceptedMaxSeconds int64 `json:"acceptedMaxSeconds"`
	RenewBeforeSeconds int64 `json:"renewBeforeSeconds"`
	StopBeforeSeconds  int64 `json:"stopBeforeSeconds"`
	ClockSkewSeconds   int64 `json:"clockSkewSeconds"`
}

type Consumer struct {
	ID                string         `json:"id"`
	Enabled           *bool          `json:"enabled"`
	ServiceAccount    ServiceAccount `json:"serviceAccount"`
	Secret            Ref            `json:"secret"`
	CADeployment      Deployment     `json:"caDeployment"`
	ReloadPolicy      string         `json:"reloadPolicy"`
	PermissionProfile string         `json:"permissionProfile"`
}

// Provider is decoded as a discriminated union; validate rejects fields from another mode.
type Provider struct {
	Type                  string          `json:"type"`
	ServiceAccount        *ServiceAccount `json:"serviceAccount,omitempty"`
	Secret                *Ref            `json:"secret,omitempty"`
	LongLived             *bool           `json:"longLived,omitempty"`
	RotationPeriodSeconds int64           `json:"rotationPeriodSeconds,omitempty"`
	TokenEndpoint         string          `json:"tokenEndpoint,omitempty"`
	TrustSecret           *Ref            `json:"trustSecret,omitempty"`
	ClientID              string          `json:"clientID,omitempty"`
	ClientSecret          *Ref            `json:"clientSecret,omitempty"`
	SubjectTokenVolume    string          `json:"subjectTokenVolume,omitempty"`
	SubjectTokenAudience  string          `json:"subjectTokenAudience,omitempty"`
	Audience              string          `json:"audience,omitempty"`
	Scopes                []string        `json:"scopes,omitempty"`
	AcceptedMinSeconds    int64           `json:"acceptedMinSeconds,omitempty"`
	AcceptedMaxSeconds    int64           `json:"acceptedMaxSeconds,omitempty"`
}

// Parse returns only sanitized errors: enrollment can contain accidentally pasted credentials.
func Parse(reader io.Reader) (*Registry, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
	if err != nil || len(data) > MaxBytes || !json.Valid(data) {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueKeys(decoder, 0); err != nil {
		return nil, ErrInvalid
	}
	var raw any
	if json.Unmarshal(data, &raw) != nil || !exactFields(raw, reflect.TypeOf(Registry{})) {
		return nil, ErrInvalid
	}
	var registry Registry
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil || registry.Validate() != nil {
		return nil, ErrInvalid
	}
	return &registry, nil
}

func uniqueKeys(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]bool{}
		for decoder.More() {
			token, err = decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || keys[key] {
				return ErrInvalid
			}
			keys[key] = true
			if uniqueKeys(decoder, depth+1) != nil {
				return ErrInvalid
			}
		}
	case '[':
		for decoder.More() {
			if uniqueKeys(decoder, depth+1) != nil {
				return ErrInvalid
			}
		}
	default:
		return ErrInvalid
	}
	_, err = decoder.Token()
	return err
}

func name(value string) bool {
	return len(value) > 0 && len(value) <= 63 && namePattern.MatchString(value)
}
func identity(value string) bool     { return uuidPattern.MatchString(value) }
func (r Ref) valid() bool            { return name(r.Namespace) && objectName(r.Name) && identity(r.UID) }
func (s ServiceAccount) valid() bool { return objectName(s.Name) && identity(s.UID) }
func text(value string) bool {
	return value != "" && len(value) <= 2048 && !strings.ContainsAny(value, "\x00\r\n\t ")
}
func distinctText(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !text(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
func objectName(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if !name(part) {
			return false
		}
	}
	return true
}

func exactFields(value any, typ reflect.Type) bool {
	if typ.Kind() == reflect.Pointer {
		if value == nil {
			return true
		}
		return exactFields(value, typ.Elem())
	}
	switch typ.Kind() {
	case reflect.Struct:
		fields, ok := value.(map[string]any)
		if !ok {
			return false
		}
		if typ == reflect.TypeOf(Provider{}) {
			modes := map[string][]string{
				"SecretIssuer":       {"type", "serviceAccount", "secret", "longLived", "rotationPeriodSeconds"},
				"OAuthTokenExchange": {"type", "tokenEndpoint", "trustSecret", "clientID", "clientSecret", "subjectTokenVolume", "subjectTokenAudience", "audience", "scopes", "acceptedMinSeconds", "acceptedMaxSeconds"},
			}
			mode, _ := fields["type"].(string)
			allowed := map[string]bool{}
			for _, key := range modes[mode] {
				allowed[key] = true
			}
			for key := range fields {
				if !allowed[key] {
					return false
				}
			}
		}
		allowed := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			parts := strings.Split(field.Tag.Get("json"), ",")
			allowed[parts[0]] = field.Type
			if len(parts) == 1 {
				if _, present := fields[parts[0]]; !present {
					return false
				}
			}
		}
		for key, item := range fields {
			fieldType, known := allowed[key]
			if !known || !exactFields(item, fieldType) {
				return false
			}
		}
	case reflect.String:
		if _, ok := value.(string); !ok {
			return false
		}
	case reflect.Bool:
		if _, ok := value.(bool); !ok {
			return false
		}
	case reflect.Int, reflect.Int64:
		if _, ok := value.(float64); !ok {
			return false
		}
	case reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range items {
			if !exactFields(item, typ.Elem()) {
				return false
			}
		}
	}
	return true
}

// APIEndpoint accepts only canonical, credential-free TLS API endpoints.
func APIEndpoint(value string) bool { return endpoint(value, false) }

func endpoint(value string, token bool) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		strings.Contains(value, "#") || !text(value) {
		return false
	}
	if !token && (u.Path != "" || u.Port() == "") {
		return false
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil && ip.String() != host {
		return false
	}
	if strings.ToLower(u.Host) != u.Host || (net.ParseIP(host) == nil && !objectName(host)) {
		return false
	}
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return false
		}
	}
	return true
}

func (l Lifetime) valid() bool {
	return l.AcceptedMaxSeconds >= l.RequestedSeconds && l.RequestedSeconds >= l.AcceptedMinSeconds &&
		l.AcceptedMinSeconds > l.RenewBeforeSeconds && l.RenewBeforeSeconds > l.StopBeforeSeconds &&
		l.StopBeforeSeconds > l.ClockSkewSeconds && l.ClockSkewSeconds > 0 && l.AcceptedMaxSeconds <= 7*86400
}

func (p Provider) refs() []Ref {
	var refs []Ref
	for _, ref := range []*Ref{p.Secret, p.TrustSecret, p.ClientSecret} {
		if ref != nil {
			refs = append(refs, *ref)
		}
	}
	return refs
}

func (p Provider) valid(namespace string, principal Principal) bool {
	for _, ref := range p.refs() {
		if !ref.valid() {
			return false
		}
	}
	oauthFields := p.TokenEndpoint != "" || p.TrustSecret != nil || p.ClientSecret != nil || p.ClientID != "" ||
		p.SubjectTokenVolume != "" || p.SubjectTokenAudience != "" || p.Audience != "" || len(p.Scopes) != 0 ||
		p.AcceptedMinSeconds != 0 || p.AcceptedMaxSeconds != 0
	switch p.Type {
	case "SecretIssuer":
		if oauthFields || p.ServiceAccount == nil || !p.ServiceAccount.valid() || p.Secret == nil || p.LongLived == nil {
			return false
		}
		if *p.LongLived && (p.RotationPeriodSeconds <= 0 || p.RotationPeriodSeconds > 365*86400) {
			return false
		}
		if !*p.LongLived && p.RotationPeriodSeconds != 0 {
			return false
		}
		expected := "system:serviceaccount:" + namespace + ":" + p.ServiceAccount.Name
		if principal.Username != expected {
			return false
		}
		expectedGroups := map[string]bool{"system:serviceaccounts": true, "system:serviceaccounts:" + namespace: true, "system:authenticated": true}
		if len(principal.Groups) != len(expectedGroups) {
			return false
		}
		for _, group := range principal.Groups {
			if !expectedGroups[group] {
				return false
			}
		}
		return true
	case "OAuthTokenExchange":
		if p.ServiceAccount != nil || p.Secret != nil || p.LongLived != nil || p.RotationPeriodSeconds != 0 || strings.HasPrefix(principal.Username, "system:") {
			return false
		}
		for _, group := range principal.Groups {
			if strings.HasPrefix(group, "system:") && group != "system:authenticated" {
				return false
			}
		}
		return endpoint(p.TokenEndpoint, true) && p.TrustSecret != nil && p.ClientSecret != nil &&
			text(p.ClientID) && name(p.SubjectTokenVolume) && text(p.SubjectTokenAudience) && text(p.Audience) && distinctText(p.Scopes) &&
			p.AcceptedMinSeconds >= 600 && p.AcceptedMaxSeconds > p.AcceptedMinSeconds && p.AcceptedMaxSeconds <= 86400
	default:
		return false
	}
}

// Validate checks authority references before any API client or network request exists.
func (r *Registry) Validate() error {
	if r == nil || r.SchemaVersion != 1 || !identity(r.ManagementUID) || r.Clusters == nil || len(r.Clusters) > 100 {
		return ErrInvalid
	}
	ids, clusterUIDs, endpoints := map[string]bool{}, map[string]bool{}, map[string]bool{}
	outputRefs, sourceRefs, saIDs, deployments := map[string]bool{}, map[string]string{}, map[string]bool{}, map[string]bool{}
	issuerRefs := map[string]bool{}
	subjectVolumes := map[string]string{}
	for _, c := range r.Clusters {
		if c.Enabled == nil || !name(c.ID) || ids[c.ID] || !endpoint(c.Endpoint, false) || endpoints[c.Endpoint] || !identity(c.KubeSystemUID) ||
			clusterUIDs[c.KubeSystemUID] || !hashPattern.MatchString(c.CASHA256) || !name(c.IdentityNamespace) ||
			!distinctText(c.Audiences) || !text(c.ExpectedIssuer.Username) || !distinctText(c.ExpectedIssuer.Groups) ||
			!c.Provider.valid(c.IdentityNamespace, c.ExpectedIssuer) || !c.Lifetime.valid() || len(c.Consumers) == 0 || len(c.Consumers) > 100 {
			return ErrInvalid
		}
		if c.Provider.Type == "OAuthTokenExchange" {
			volume := c.Provider.SubjectTokenVolume
			if volume == "management-api" || (subjectVolumes[volume] != "" && subjectVolumes[volume] != c.Provider.SubjectTokenAudience) {
				return ErrInvalid
			}
			subjectVolumes[volume] = c.Provider.SubjectTokenAudience
		}
		ids[c.ID], clusterUIDs[c.KubeSystemUID], endpoints[c.Endpoint] = true, true, true
		for _, ref := range c.Provider.refs() {
			key := ref.Namespace + "/" + ref.Name
			if outputRefs[key] || (sourceRefs[key] != "" && (sourceRefs[key] != ref.UID || c.Provider.Type == "SecretIssuer" || issuerRefs[key])) {
				return ErrInvalid
			}
			sourceRefs[key] = ref.UID
			issuerRefs[key] = c.Provider.Type == "SecretIssuer"
		}
		if c.Provider.ServiceAccount != nil {
			key := c.KubeSystemUID + "/" + c.IdentityNamespace + "/" + c.Provider.ServiceAccount.Name
			saIDs[key] = true
		}
		for _, consumer := range c.Consumers {
			ref := consumer.Secret
			key := ref.Namespace + "/" + ref.Name
			saKey := c.KubeSystemUID + "/" + c.IdentityNamespace + "/" + consumer.ServiceAccount.Name
			dep := consumer.CADeployment
			depKey := dep.Namespace + "/" + dep.Name
			if !name(consumer.ID) || ids[consumer.ID] || !consumer.ServiceAccount.valid() || saIDs[saKey] || !ref.valid() ||
				outputRefs[key] || sourceRefs[key] != "" || !name(dep.Namespace) || !objectName(dep.Name) || !identity(dep.UID) ||
				ref.Namespace != dep.Namespace || deployments[depKey] || !strings.HasPrefix(dep.ImageDigest, "sha256:") || !hashPattern.MatchString(strings.TrimPrefix(dep.ImageDigest, "sha256:")) ||
				(consumer.ReloadPolicy != "TokenFile" && consumer.ReloadPolicy != "StopStart") || consumer.PermissionProfile != "ca-read-events" ||
				(consumer.Enabled == nil || (*consumer.Enabled && !*c.Enabled)) {
				return ErrInvalid
			}
			ids[consumer.ID], outputRefs[key], saIDs[saKey], deployments[depKey] = true, true, true, true
		}
	}
	return nil
}
