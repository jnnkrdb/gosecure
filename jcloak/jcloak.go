package jcloak

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jnnkrdb/gosecure/jcloak/jwx"

	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/segmentio/ksuid"
)

type JCloak struct {
	basePath    string
	certsCache  sync.Map
	certsLock   sync.Mutex
	restyClient *resty.Client
	Config      struct {
		CertsInvalidateTime time.Duration
		authAdminRealms     string
		authRealms          string
		tokenEndpoint       string
		logoutEndpoint      string
		openIDConnect       string
	}
}

func (jc *JCloak) getRequest(ctx context.Context) *resty.Request {
	var err HTTPErrorResponse
	return injectTracingHeaders(
		ctx, jc.restyClient.R().
			SetContext(ctx).
			SetError(&err),
	)
}

func (jc *JCloak) getRequestWithBearerAuthNoCache(ctx context.Context, token string) *resty.Request {
	return jc.getRequest(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json").
		SetHeader("Cache-Control", "no-cache")
}

func (jc *JCloak) getRequestWithBearerAuth(ctx context.Context, token string) *resty.Request {
	return jc.getRequest(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json")
}

func (jc *JCloak) getRequestWithBearerAuthXMLHeader(ctx context.Context, token string) *resty.Request {
	return jc.getRequest(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/xml;charset=UTF-8")
}

func (jc *JCloak) getRequestWithBasicAuth(ctx context.Context, clientID, clientSecret string) *resty.Request {
	req := jc.getRequest(ctx).
		SetHeader("Content-Type", "application/x-www-form-urlencoded")
	// Public client doesn't require Basic Auth
	if len(clientID) > 0 && len(clientSecret) > 0 {
		httpBasicAuth := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
		req.SetHeader("Authorization", "Basic "+httpBasicAuth)
	}

	return req
}

func (jc *JCloak) getRequestingParty(ctx context.Context, token string, realm string, options RequestingPartyTokenOptions, res interface{}) (*resty.Response, error) {
	return jc.getRequestWithBearerAuth(ctx, token).
		SetFormData(options.FormData()).
		SetFormDataFromValues(url.Values{"permission": PStringSlice(options.Permissions)}).
		SetResult(&res).
		Post(jc.getRealmURL(realm, jc.Config.tokenEndpoint))
}

// RestyClient returns the internal resty jc.
// This can be used to configure the jc.
func (jc *JCloak) RestyClient() *resty.Client {
	return jc.restyClient
}

// SetRestyClient overwrites the internal resty jc.
func (jc *JCloak) SetRestyClient(restyClient *resty.Client) {
	jc.restyClient = restyClient
}

func (jc *JCloak) getRealmURL(realm string, path ...string) string {
	path = append([]string{jc.basePath, jc.Config.authRealms, realm}, path...)
	return makeURL(path...)
}

func (jc *JCloak) getAdminRealmURL(realm string, path ...string) string {
	path = append([]string{jc.basePath, jc.Config.authAdminRealms, realm}, path...)
	return makeURL(path...)
}

// =============== =============== =============== =============== =============== =============== =============== ===============
// Keycloak client =============== =============== =============== =============== =============== =============== ===============
// =============== =============== =============== =============== =============== =============== =============== ===============

// NewClient creates a new Client
func NewClient(basePath string, options ...func(*JCloak)) *JCloak {
	jc := JCloak{
		basePath:    strings.TrimRight(basePath, urlSeparator),
		restyClient: resty.New(),
	}

	jc.Config.CertsInvalidateTime = 10 * time.Minute
	jc.Config.authAdminRealms = makeURL("admin", "realms")
	jc.Config.authRealms = makeURL("realms")
	jc.Config.tokenEndpoint = makeURL("protocol", "openid-connect", "token")
	jc.Config.logoutEndpoint = makeURL("protocol", "openid-connect", "logout")
	jc.Config.openIDConnect = makeURL("protocol", "openid-connect")

	for _, option := range options {
		option(&jc)
	}

	return &jc
}

// ================== ================== ================== ================== ================== ================== ================== ==================
// Keycloak Functions ================== ================== ================== ================== ================== ================== ==================
// ================== ================== ================== ================== ================== ================== ================== ==================

// GetServerInfo fetches the server info.
func (jc *JCloak) GetServerInfo(ctx context.Context, accessToken string) ([]*ServerInfoRepresentation, error) {
	errMessage := "could not get server info"
	var result []*ServerInfoRepresentation

	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(makeURL(jc.basePath, "admin", "realms"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetUserInfo calls the UserInfo endpoint
func (jc *JCloak) GetUserInfo(ctx context.Context, accessToken, realm string) (*UserInfo, error) {
	const errMessage = "could not get user info"

	var result UserInfo
	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(jc.getRealmURL(realm, jc.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRawUserInfo calls the UserInfo endpoint and returns a raw json object
func (jc *JCloak) GetRawUserInfo(ctx context.Context, accessToken, realm string) (map[string]interface{}, error) {
	const errMessage = "could not get user info"

	var result map[string]interface{}
	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(jc.getRealmURL(realm, jc.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

func (jc *JCloak) getNewCerts(ctx context.Context, realm string) (*CertResponse, error) {
	const errMessage = "could not get newCerts"

	var result CertResponse
	resp, err := jc.getRequest(ctx).
		SetResult(&result).
		Get(jc.getRealmURL(realm, jc.Config.openIDConnect, "certs"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetCerts fetches certificates for the given realm from the public /open-id-connect/certs endpoint
func (jc *JCloak) GetCerts(ctx context.Context, realm string) (*CertResponse, error) {
	const errMessage = "could not get certs"

	if cert, ok := jc.certsCache.Load(realm); ok {
		return cert.(*CertResponse), nil
	}

	jc.certsLock.Lock()
	defer jc.certsLock.Unlock()

	if cert, ok := jc.certsCache.Load(realm); ok {
		return cert.(*CertResponse), nil
	}

	cert, err := jc.getNewCerts(ctx, realm)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	jc.certsCache.Store(realm, cert)
	time.AfterFunc(jc.Config.CertsInvalidateTime, func() {
		jc.certsCache.Delete(realm)
	})

	return cert, nil
}

// GetIssuer gets the issuer of the given realm
func (jc *JCloak) GetIssuer(ctx context.Context, realm string) (*IssuerResponse, error) {
	const errMessage = "could not get issuer"

	var result IssuerResponse
	resp, err := jc.getRequest(ctx).
		SetResult(&result).
		Get(jc.getRealmURL(realm))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// RetrospectToken calls the openid-connect introspect endpoint
func (jc *JCloak) RetrospectToken(ctx context.Context, accessToken, clientID, clientSecret, realm string) (*IntroSpectTokenResult, error) {
	const errMessage = "could not introspect requesting party token"

	var result IntroSpectTokenResult
	resp, err := jc.getRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"token_type_hint": "requesting_party_token",
			"token":           accessToken,
		}).
		SetResult(&result).
		Post(jc.getRealmURL(realm, jc.Config.tokenEndpoint, "introspect"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

func (jc *JCloak) decodeAccessTokenWithClaims(ctx context.Context, accessToken, realm string, claims jwt.Claims) (*jwt.Token, error) {
	const errMessage = "could not decode access token"
	accessToken = strings.Replace(accessToken, "Bearer ", "", 1)

	decodedHeader, err := jwx.DecodeAccessTokenHeader(accessToken)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	certResult, err := jc.GetCerts(ctx, realm)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}
	if certResult.Keys == nil {
		return nil, errors.Wrap(errors.New("there is no keys to decode the token"), errMessage)
	}
	usedKey := findUsedKey(decodedHeader.Kid, *certResult.Keys)
	if usedKey == nil {
		return nil, errors.Wrap(errors.New("cannot find a key to decode the token"), errMessage)
	}

	if strings.HasPrefix(decodedHeader.Alg, "ES") {
		return jwx.DecodeAccessTokenECDSACustomClaims(accessToken, usedKey.X, usedKey.Y, usedKey.Crv, claims)
	} else if strings.HasPrefix(decodedHeader.Alg, "RS") {
		return jwx.DecodeAccessTokenRSACustomClaims(accessToken, usedKey.E, usedKey.N, claims)
	}
	return nil, fmt.Errorf("unsupported algorithm")
}

// DecodeAccessToken decodes the accessToken
func (jc *JCloak) DecodeAccessToken(ctx context.Context, accessToken, realm string) (*jwt.Token, *jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	token, err := jc.decodeAccessTokenWithClaims(ctx, accessToken, realm, claims)
	if err != nil {
		return nil, nil, err
	}
	return token, &claims, nil
}

// DecodeAccessTokenCustomClaims decodes the accessToken and writes claims into the given claims
func (jc *JCloak) DecodeAccessTokenCustomClaims(ctx context.Context, accessToken, realm string, claims jwt.Claims) (*jwt.Token, error) {
	return jc.decodeAccessTokenWithClaims(ctx, accessToken, realm, claims)
}

// GetToken uses TokenOptions to fetch a token.
func (jc *JCloak) GetToken(ctx context.Context, realm string, options TokenOptions) (*JWT, error) {
	const errMessage = "could not get token"

	var token JWT
	var req *resty.Request

	if !NilOrEmpty(options.ClientSecret) {
		req = jc.getRequestWithBasicAuth(ctx, *options.ClientID, *options.ClientSecret)
	} else {
		req = jc.getRequest(ctx)
	}

	resp, err := req.SetFormData(options.FormData()).
		SetResult(&token).
		Post(jc.getRealmURL(realm, jc.Config.tokenEndpoint))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &token, nil
}

// GetRequestingPartyToken returns a requesting party token with permissions granted by the server
func (jc *JCloak) GetRequestingPartyToken(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*JWT, error) {
	const errMessage = "could not get requesting party token"

	var res JWT

	resp, err := jc.getRequestingParty(ctx, token, realm, options, &res)
	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &res, nil
}

// GetRequestingPartyPermissions returns a requesting party permissions granted by the server
func (jc *JCloak) GetRequestingPartyPermissions(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*[]RequestingPartyPermission, error) {
	const errMessage = "could not get requesting party token"

	var res []RequestingPartyPermission

	options.ResponseMode = StringP("permissions")

	resp, err := jc.getRequestingParty(ctx, token, realm, options, &res)
	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &res, nil
}

// GetRequestingPartyPermissionDecision returns a requesting party permission decision granted by the server
func (jc *JCloak) GetRequestingPartyPermissionDecision(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*RequestingPartyPermissionDecision, error) {
	const errMessage = "could not get requesting party token"

	var res RequestingPartyPermissionDecision

	options.ResponseMode = StringP("decision")

	resp, err := jc.getRequestingParty(ctx, token, realm, options, &res)
	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &res, nil
}

// RefreshToken refreshes the given token.
// May return a *APIError with further details about the issue.
func (jc *JCloak) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret, realm string) (*JWT, error) {
	return jc.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("refresh_token"),
		RefreshToken: &refreshToken,
	})
}

// LoginAdmin performs a login with Admin client
func (jc *JCloak) LoginAdmin(ctx context.Context, username, password, realm string) (*JWT, error) {
	return jc.GetToken(ctx, realm, TokenOptions{
		ClientID:  StringP(adminClientID),
		GrantType: StringP("password"),
		Username:  &username,
		Password:  &password,
	})
}

// LoginClient performs a login with client credentials
func (jc *JCloak) LoginClient(ctx context.Context, clientID, clientSecret, realm string) (*JWT, error) {
	return jc.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("client_credentials"),
	})
}

// LoginClientTokenExchange will exchange the presented token for a user's token
// Requires Token-Exchange is enabled: https://www.keycloak.org/docs/latest/securing_apps/index.html#_token-exchange
func (jc *JCloak) LoginClientTokenExchange(ctx context.Context, clientID, token, clientSecret, realm, targetClient, userID string) (*JWT, error) {
	tokenOptions := TokenOptions{
		ClientID:           &clientID,
		ClientSecret:       &clientSecret,
		GrantType:          StringP("urn:ietf:params:oauth:grant-type:token-exchange"),
		SubjectToken:       &token,
		RequestedTokenType: StringP("urn:ietf:params:oauth:token-type:refresh_token"),
		Audience:           &targetClient,
	}
	if userID != "" {
		tokenOptions.RequestedSubject = &userID
	}
	return jc.GetToken(ctx, realm, tokenOptions)
}

// LoginClientSignedJWT performs a login with client credentials and signed jwt claims
func (jc *JCloak) LoginClientSignedJWT(
	ctx context.Context,
	clientID,
	realm string,
	key interface{},
	signedMethod jwt.SigningMethod,
	expiresAt *jwt.NumericDate,
) (*JWT, error) {
	claims := jwt.RegisteredClaims{
		ExpiresAt: expiresAt,
		Issuer:    clientID,
		Subject:   clientID,
		ID:        ksuid.New().String(),
		Audience: jwt.ClaimStrings{
			jc.getRealmURL(realm),
		},
	}
	assertion, err := jwx.SignClaims(claims, key, signedMethod)
	if err != nil {
		return nil, err
	}

	return jc.GetToken(ctx, realm, TokenOptions{
		ClientID:            &clientID,
		GrantType:           StringP("client_credentials"),
		ClientAssertionType: StringP("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
		ClientAssertion:     &assertion,
	})
}

// Login performs a login with user credentials and a client
func (jc *JCloak) Login(ctx context.Context, clientID, clientSecret, realm, username, password string) (*JWT, error) {
	return jc.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("password"),
		Username:     &username,
		Password:     &password,
	})
}

// LoginOtp performs a login with user credentials and otp token
func (jc *JCloak) LoginOtp(ctx context.Context, clientID, clientSecret, realm, username, password, totp string) (*JWT, error) {
	return jc.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("password"),
		Username:     &username,
		Password:     &password,
		Totp:         &totp,
	})
}

// Logout logs out users with refresh token
func (jc *JCloak) Logout(ctx context.Context, clientID, clientSecret, realm, refreshToken string) error {
	const errMessage = "could not logout"

	resp, err := jc.getRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(jc.getRealmURL(realm, jc.Config.logoutEndpoint))

	return checkForError(resp, err, errMessage)
}

// LogoutPublicClient performs a logout using a public client and the accessToken.
func (jc *JCloak) LogoutPublicClient(ctx context.Context, clientID, realm, accessToken, refreshToken string) error {
	const errMessage = "could not logout public client"

	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(jc.getRealmURL(realm, jc.Config.logoutEndpoint))

	return checkForError(resp, err, errMessage)
}

// LogoutAllSessions logs out all sessions of a user given an id.
func (jc *JCloak) LogoutAllSessions(ctx context.Context, accessToken, realm, userID string) error {
	const errMessage = "could not logout"

	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		Post(jc.getAdminRealmURL(realm, "users", userID, "logout"))

	return checkForError(resp, err, errMessage)
}

// RevokeUserConsents revokes the given user consent.
func (jc *JCloak) RevokeUserConsents(ctx context.Context, accessToken, realm, userID, clientID string) error {
	const errMessage = "could not revoke consents"

	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		Delete(jc.getAdminRealmURL(realm, "users", userID, "consents", clientID))

	return checkForError(resp, err, errMessage)
}

// LogoutUserSession logs out a single sessions of a user given a session id
func (jc *JCloak) LogoutUserSession(ctx context.Context, accessToken, realm, session string) error {
	const errMessage = "could not logout"

	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		Delete(jc.getAdminRealmURL(realm, "sessions", session))

	return checkForError(resp, err, errMessage)
}

// ExecuteActionsEmail executes an actions email
func (jc *JCloak) ExecuteActionsEmail(ctx context.Context, token, realm string, params ExecuteActionsEmail) error {
	const errMessage = "could not execute actions email"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return errors.Wrap(err, errMessage)
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(params.Actions).
		SetQueryParams(queryParams).
		Put(jc.getAdminRealmURL(realm, "users", *(params.UserID), "execute-actions-email"))

	return checkForError(resp, err, errMessage)
}

// SendVerifyEmail sends a verification e-mail to a user.
func (jc *JCloak) SendVerifyEmail(ctx context.Context, token, userID, realm string, params ...SendVerificationMailParams) error {
	const errMessage = "could not execute actions email"

	queryParams := map[string]string{}
	if params != nil {
		if params[0].ClientID != nil {
			queryParams["client_id"] = *params[0].ClientID
		}

		if params[0].RedirectURI != nil {
			queryParams["redirect_uri"] = *params[0].RedirectURI
		}
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetQueryParams(queryParams).
		Put(jc.getAdminRealmURL(realm, "users", userID, "send-verify-email"))

	return checkForError(resp, err, errMessage)
}

// CreateGroup creates a new group.
func (jc *JCloak) CreateGroup(ctx context.Context, token, realm string, group Group) (string, error) {
	const errMessage = "could not create group"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(group).
		Post(jc.getAdminRealmURL(realm, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}
	return getID(resp), nil
}

// CreateChildGroup creates a new child group
func (jc *JCloak) CreateChildGroup(ctx context.Context, token, realm, groupID string, group Group) (string, error) {
	const errMessage = "could not create child group"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(group).
		Post(jc.getAdminRealmURL(realm, "groups", groupID, "children"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// CreateComponent creates the given component.
func (jc *JCloak) CreateComponent(ctx context.Context, token, realm string, component Component) (string, error) {
	const errMessage = "could not create component"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(component).
		Post(jc.getAdminRealmURL(realm, "components"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// CreateClient creates the given jc.
func (jc *JCloak) CreateClient(ctx context.Context, accessToken, realm string, newClient Client) (string, error) {
	const errMessage = "could not create client"

	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		SetBody(newClient).
		Post(jc.getAdminRealmURL(realm, "clients"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// CreateClientRepresentation creates a new client representation
func (jc *JCloak) CreateClientRepresentation(ctx context.Context, token, realm string, newClient Client) (*Client, error) {
	const errMessage = "could not create client representation"

	var result Client

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(newClient).
		Post(jc.getRealmURL(realm, "clients-registrations", "default"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateClientRole creates a new role for a client
func (jc *JCloak) CreateClientRole(ctx context.Context, token, realm, idOfClient string, role Role) (string, error) {
	const errMessage = "could not create client role"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Post(jc.getAdminRealmURL(realm, "clients", idOfClient, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// CreateClientScope creates a new client scope
func (jc *JCloak) CreateClientScope(ctx context.Context, token, realm string, scope ClientScope) (string, error) {
	const errMessage = "could not create client scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Post(jc.getAdminRealmURL(realm, "client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// CreateClientScopeProtocolMapper creates a new protocolMapper under the given client scope
func (jc *JCloak) CreateClientScopeProtocolMapper(ctx context.Context, token, realm, scopeID string, protocolMapper ProtocolMappers) (string, error) {
	const errMessage = "could not create client scope protocol mapper"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(protocolMapper).
		Post(jc.getAdminRealmURL(realm, "client-scopes", scopeID, "protocol-mappers", "models"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// UpdateGroup updates the given group.
func (jc *JCloak) UpdateGroup(ctx context.Context, token, realm string, updatedGroup Group) error {
	const errMessage = "could not update group"

	if NilOrEmpty(updatedGroup.ID) {
		return errors.Wrap(errors.New("ID of a group required"), errMessage)
	}
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(updatedGroup).
		Put(jc.getAdminRealmURL(realm, "groups", PString(updatedGroup.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateClient updates the given Client
func (jc *JCloak) UpdateClient(ctx context.Context, token, realm string, updatedClient Client) error {
	const errMessage = "could not update client"

	if NilOrEmpty(updatedClient.ID) {
		return errors.Wrap(errors.New("ID of a client required"), errMessage)
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(updatedClient).
		Put(jc.getAdminRealmURL(realm, "clients", PString(updatedClient.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateClientRepresentation updates the given client representation
func (jc *JCloak) UpdateClientRepresentation(ctx context.Context, accessToken, realm string, updatedClient Client) (*Client, error) {
	const errMessage = "could not update client representation"

	if NilOrEmpty(updatedClient.ID) {
		return nil, errors.Wrap(errors.New("ID of a client required"), errMessage)
	}

	var result Client

	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		SetBody(updatedClient).
		Put(jc.getRealmURL(realm, "clients-registrations", "default", PString(updatedClient.ClientID)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateRole updates the given role.
func (jc *JCloak) UpdateRole(ctx context.Context, token, realm, idOfClient string, role Role) error {
	const errMessage = "could not update role"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(jc.getAdminRealmURL(realm, "clients", idOfClient, "roles", PString(role.Name)))

	return checkForError(resp, err, errMessage)
}

// UpdateClientScope updates the given client scope.
func (jc *JCloak) UpdateClientScope(ctx context.Context, token, realm string, scope ClientScope) error {
	const errMessage = "could not update client scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Put(jc.getAdminRealmURL(realm, "client-scopes", PString(scope.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateClientScopeProtocolMapper updates the given protocol mapper for a client scope
func (jc *JCloak) UpdateClientScopeProtocolMapper(ctx context.Context, token, realm, scopeID string, protocolMapper ProtocolMappers) error {
	const errMessage = "could not update client scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(protocolMapper).
		Put(jc.getAdminRealmURL(realm, "client-scopes", scopeID, "protocol-mappers", "models", PString(protocolMapper.ID)))

	return checkForError(resp, err, errMessage)
}

// DeleteGroup deletes the group with the given groupID.
func (jc *JCloak) DeleteGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not delete group"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// DeleteClient deletes a given client
func (jc *JCloak) DeleteClient(ctx context.Context, token, realm, idOfClient string) error {
	const errMessage = "could not delete client"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// DeleteComponent deletes the component with the given id.
func (jc *JCloak) DeleteComponent(ctx context.Context, token, realm, componentID string) error {
	const errMessage = "could not delete component"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "components", componentID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRepresentation deletes a given client representation.
func (jc *JCloak) DeleteClientRepresentation(ctx context.Context, accessToken, realm, clientID string) error {
	const errMessage = "could not delete client representation"

	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		Delete(jc.getRealmURL(realm, "clients-registrations", "default", clientID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRole deletes a given role.
func (jc *JCloak) DeleteClientRole(ctx context.Context, token, realm, idOfClient, roleName string) error {
	const errMessage = "could not delete client role"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "clients", idOfClient, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScope deletes the scope with the given id.
func (jc *JCloak) DeleteClientScope(ctx context.Context, token, realm, scopeID string) error {
	const errMessage = "could not delete client scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScopeProtocolMapper deletes the given protocol mapper from the client scope
func (jc *JCloak) DeleteClientScopeProtocolMapper(ctx context.Context, token, realm, scopeID, protocolMapperID string) error {
	const errMessage = "could not delete client scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "client-scopes", scopeID, "protocol-mappers", "models", protocolMapperID))

	return checkForError(resp, err, errMessage)
}

// GetClient returns a client
func (jc *JCloak) GetClient(ctx context.Context, token, realm, idOfClient string) (*Client, error) {
	const errMessage = "could not get client"

	var result Client

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientRepresentation returns a client representation
func (jc *JCloak) GetClientRepresentation(ctx context.Context, accessToken, realm, clientID string) (*Client, error) {
	const errMessage = "could not get client representation"

	var result Client

	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(jc.getRealmURL(realm, "clients-registrations", "default", clientID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetAdapterConfiguration returns a adapter configuration
func (jc *JCloak) GetAdapterConfiguration(ctx context.Context, accessToken, realm, clientID string) (*AdapterConfiguration, error) {
	const errMessage = "could not get adapter configuration"

	var result AdapterConfiguration

	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(jc.getRealmURL(realm, "clients-registrations", "install", clientID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientsDefaultScopes returns a list of the client's default scopes
func (jc *JCloak) GetClientsDefaultScopes(ctx context.Context, token, realm, idOfClient string) ([]*ClientScope, error) {
	const errMessage = "could not get clients default scopes"

	var result []*ClientScope

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "default-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddDefaultScopeToClient adds a client scope to the list of client's default scopes
func (jc *JCloak) AddDefaultScopeToClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not add default scope to client"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Put(jc.getAdminRealmURL(realm, "clients", idOfClient, "default-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// RemoveDefaultScopeFromClient removes a client scope from the list of client's default scopes
func (jc *JCloak) RemoveDefaultScopeFromClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not remove default scope from client"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "clients", idOfClient, "default-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetClientsOptionalScopes returns a list of the client's optional scopes
func (jc *JCloak) GetClientsOptionalScopes(ctx context.Context, token, realm, idOfClient string) ([]*ClientScope, error) {
	const errMessage = "could not get clients optional scopes"

	var result []*ClientScope

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "optional-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddOptionalScopeToClient adds a client scope to the list of client's optional scopes
func (jc *JCloak) AddOptionalScopeToClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not add optional scope to client"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Put(jc.getAdminRealmURL(realm, "clients", idOfClient, "optional-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// RemoveOptionalScopeFromClient deletes a client scope from the list of client's optional scopes
func (jc *JCloak) RemoveOptionalScopeFromClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not remove optional scope from client"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "clients", idOfClient, "optional-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetDefaultOptionalClientScopes returns a list of default realm optional scopes
func (jc *JCloak) GetDefaultOptionalClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get default optional client scopes"

	var result []*ClientScope

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "default-optional-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetDefaultDefaultClientScopes returns a list of default realm default scopes
func (jc *JCloak) GetDefaultDefaultClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get default client scopes"

	var result []*ClientScope

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "default-default-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScope returns a clientscope
func (jc *JCloak) GetClientScope(ctx context.Context, token, realm, scopeID string) (*ClientScope, error) {
	const errMessage = "could not get client scope"

	var result ClientScope

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "client-scopes", scopeID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientScopes returns all client scopes
func (jc *JCloak) GetClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get client scopes"

	var result []*ClientScope

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeProtocolMappers returns all protocol mappers of a client scope
func (jc *JCloak) GetClientScopeProtocolMappers(ctx context.Context, token, realm, scopeID string) ([]*ProtocolMappers, error) {
	const errMessage = "could not get client scope protocol mappers"

	var result []*ProtocolMappers

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "client-scopes", scopeID, "protocol-mappers", "models"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeProtocolMapper returns a protocol mapper of a client scope
func (jc *JCloak) GetClientScopeProtocolMapper(ctx context.Context, token, realm, scopeID, protocolMapperID string) (*ProtocolMappers, error) {
	const errMessage = "could not get client scope protocol mappers"

	var result *ProtocolMappers

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "client-scopes", scopeID, "protocol-mappers", "models", protocolMapperID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappings returns all scope mappings for the client
func (jc *JCloak) GetClientScopeMappings(ctx context.Context, token, realm, idOfClient string) (*MappingsRepresentation, error) {
	const errMessage = "could not get all scope mappings for the client"

	var result *MappingsRepresentation

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsRealmRoles returns realm-level roles associated with the client’s scope
func (jc *JCloak) GetClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string) ([]*Role, error) {
	const errMessage = "could not get realm-level roles with the client’s scope"

	var result []*Role

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsRealmRolesAvailable returns realm-level roles that are available to attach to this client’s scope
func (jc *JCloak) GetClientScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, idOfClient string) ([]*Role, error) {
	const errMessage = "could not get available realm-level roles with the client’s scope"

	var result []*Role

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm", "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateClientScopeMappingsRealmRoles create realm-level roles to the client’s scope
func (jc *JCloak) CreateClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string, roles []Role) error {
	const errMessage = "could not create realm-level roles to the client’s scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(jc.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScopeMappingsRealmRoles deletes realm-level roles from the client’s scope
func (jc *JCloak) DeleteClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string, roles []Role) error {
	const errMessage = "could not delete realm-level roles from the client’s scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(jc.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// GetClientScopeMappingsClientRoles returns roles associated with a client’s scope
func (jc *JCloak) GetClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string) ([]*Role, error) {
	const errMessage = "could not get roles associated with a client’s scope"

	var result []*Role

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsClientRolesAvailable returns available roles associated with a client’s scope
func (jc *JCloak) GetClientScopeMappingsClientRolesAvailable(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string) ([]*Role, error) {
	const errMessage = "could not get available roles associated with a client’s scope"

	var result []*Role

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient, "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateClientScopeMappingsClientRoles creates client-level roles from the client’s scope
func (jc *JCloak) CreateClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string, roles []Role) error {
	const errMessage = "could not create client-level roles from the client’s scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(jc.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScopeMappingsClientRoles deletes client-level roles from the client’s scope
func (jc *JCloak) DeleteClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string, roles []Role) error {
	const errMessage = "could not delete client-level roles from the client’s scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(jc.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient))

	return checkForError(resp, err, errMessage)
}

// GetClientSecret returns a client's secret
func (jc *JCloak) GetClientSecret(ctx context.Context, token, realm, idOfClient string) (*CredentialRepresentation, error) {
	const errMessage = "could not get client secret"

	var result CredentialRepresentation

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "client-secret"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientServiceAccount retrieves the service account "user" for a client if enabled
func (jc *JCloak) GetClientServiceAccount(ctx context.Context, token, realm, idOfClient string) (*User, error) {
	const errMessage = "could not get client service account"

	var result User
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "service-account-user"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// RegenerateClientSecret triggers the creation of the new client secret.
func (jc *JCloak) RegenerateClientSecret(ctx context.Context, token, realm, idOfClient string) (*CredentialRepresentation, error) {
	const errMessage = "could not regenerate client secret"

	var result CredentialRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Post(jc.getAdminRealmURL(realm, "clients", idOfClient, "client-secret"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientOfflineSessions returns offline sessions associated with the client
func (jc *JCloak) GetClientOfflineSessions(ctx context.Context, token, realm, idOfClient string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get client offline sessions"

	var res []*UserSessionRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "offline-sessions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// GetClientUserSessions returns user sessions associated with the client
func (jc *JCloak) GetClientUserSessions(ctx context.Context, token, realm, idOfClient string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get client user sessions"

	var res []*UserSessionRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "user-sessions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// CreateClientProtocolMapper creates a protocol mapper in client scope
func (jc *JCloak) CreateClientProtocolMapper(ctx context.Context, token, realm, idOfClient string, mapper ProtocolMapperRepresentation) (string, error) {
	const errMessage = "could not create client protocol mapper"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Post(jc.getAdminRealmURL(realm, "clients", idOfClient, "protocol-mappers", "models"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// UpdateClientProtocolMapper updates a protocol mapper in client scope
func (jc *JCloak) UpdateClientProtocolMapper(ctx context.Context, token, realm, idOfClient, mapperID string, mapper ProtocolMapperRepresentation) error {
	const errMessage = "could not update client protocol mapper"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Put(jc.getAdminRealmURL(realm, "clients", idOfClient, "protocol-mappers", "models", mapperID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientProtocolMapper deletes a protocol mapper in client scope
func (jc *JCloak) DeleteClientProtocolMapper(ctx context.Context, token, realm, idOfClient, mapperID string) error {
	const errMessage = "could not delete client protocol mapper"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "clients", idOfClient, "protocol-mappers", "models", mapperID))

	return checkForError(resp, err, errMessage)
}

// GetKeyStoreConfig get keystoreconfig of the realm
func (jc *JCloak) GetKeyStoreConfig(ctx context.Context, token, realm string) (*KeyStoreConfig, error) {
	const errMessage = "could not get key store config"

	var result KeyStoreConfig
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "keys"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetComponents get all components in realm
func (jc *JCloak) GetComponents(ctx context.Context, token, realm string) ([]*Component, error) {
	const errMessage = "could not get components"

	var result []*Component
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "components"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetComponentsWithParams get all components in realm with query params
func (jc *JCloak) GetComponentsWithParams(ctx context.Context, token, realm string, params GetComponentsParams) ([]*Component, error) {
	const errMessage = "could not get components"
	var result []*Component

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "components"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetComponent get exactly one component by ID
func (jc *JCloak) GetComponent(ctx context.Context, token, realm string, componentID string) (*Component, error) {
	const errMessage = "could not get components"
	var result *Component

	componentURL := fmt.Sprintf("components/%s", componentID)

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, componentURL))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateComponent updates the given component
func (jc *JCloak) UpdateComponent(ctx context.Context, token, realm string, component Component) error {
	const errMessage = "could not update component"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(component).
		Put(jc.getAdminRealmURL(realm, "components", PString(component.ID)))

	return checkForError(resp, err, errMessage)
}

// GetDefaultGroups returns a list of default groups
func (jc *JCloak) GetDefaultGroups(ctx context.Context, token, realm string) ([]*Group, error) {
	const errMessage = "could not get default groups"

	var result []*Group

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "default-groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddDefaultGroup adds group to the list of default groups
func (jc *JCloak) AddDefaultGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not add default group"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Put(jc.getAdminRealmURL(realm, "default-groups", groupID))

	return checkForError(resp, err, errMessage)
}

// RemoveDefaultGroup removes group from the list of default groups
func (jc *JCloak) RemoveDefaultGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not remove default group"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "default-groups", groupID))

	return checkForError(resp, err, errMessage)
}

func (jc *JCloak) getRoleMappings(ctx context.Context, token, realm, path, objectID string) (*MappingsRepresentation, error) {
	const errMessage = "could not get role mappings"

	var result MappingsRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, path, objectID, "role-mappings"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRoleMappingByGroupID gets the role mappings by group
func (jc *JCloak) GetRoleMappingByGroupID(ctx context.Context, token, realm, groupID string) (*MappingsRepresentation, error) {
	return jc.getRoleMappings(ctx, token, realm, "groups", groupID)
}

// GetRoleMappingByUserID gets the role mappings by user
func (jc *JCloak) GetRoleMappingByUserID(ctx context.Context, token, realm, userID string) (*MappingsRepresentation, error) {
	return jc.getRoleMappings(ctx, token, realm, "users", userID)
}

// GetGroup get group with id in realm
func (jc *JCloak) GetGroup(ctx context.Context, token, realm, groupID string) (*Group, error) {
	const errMessage = "could not get group"

	var result Group

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "groups", groupID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetGroupByPath get group with path in realm
func (jc *JCloak) GetGroupByPath(ctx context.Context, token, realm, groupPath string) (*Group, error) {
	const errMessage = "could not get group"

	var result Group

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "group-by-path", groupPath))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetGroups get all groups in realm
func (jc *JCloak) GetGroups(ctx context.Context, token, realm string, params GetGroupsParams) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupsByRole gets groups assigned with a specific role of a realm
func (jc *JCloak) GetGroupsByRole(ctx context.Context, token, realm string, roleName string) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "roles", roleName, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupsByClientRole gets groups with specified roles assigned of given client within a realm
func (jc *JCloak) GetGroupsByClientRole(ctx context.Context, token, realm string, roleName string, clientID string) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", clientID, "roles", roleName, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupsCount gets the groups count in the realm
func (jc *JCloak) GetGroupsCount(ctx context.Context, token, realm string, params GetGroupsParams) (int, error) {
	const errMessage = "could not get groups count"

	var result GroupsCount
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return 0, errors.Wrap(err, errMessage)
	}
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "groups", "count"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return -1, errors.Wrap(err, errMessage)
	}

	return result.Count, nil
}

// GetGroupMembers get a list of users of group with id in realm
func (jc *JCloak) GetGroupMembers(ctx context.Context, token, realm, groupID string, params GetGroupsParams) ([]*User, error) {
	const errMessage = "could not get group members"

	var result []*User
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "groups", groupID, "members"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRoles get all roles for the given client in realm
func (jc *JCloak) GetClientRoles(ctx context.Context, token, realm, idOfClient string, params GetRoleParams) ([]*Role, error) {
	const errMessage = "could not get client roles"

	var result []*Role
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRoleByID gets role for the given client in realm using role ID
func (jc *JCloak) GetClientRoleByID(ctx context.Context, token, realm, roleID string) (*Role, error) {
	const errMessage = "could not get client role"

	var result Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "roles-by-id", roleID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientRolesByUserID returns all client roles assigned to the given user
func (jc *JCloak) GetClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error) {
	const errMessage = "could not client roles by user id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRolesByGroupID returns all client roles assigned to the given group
func (jc *JCloak) GetClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error) {
	const errMessage = "could not get client roles by group id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByRoleID returns all client composite roles associated with the given client role
func (jc *JCloak) GetCompositeClientRolesByRoleID(ctx context.Context, token, realm, idOfClient, roleID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by role id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "roles-by-id", roleID, "composites", "clients", idOfClient))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByUserID returns all client roles and composite roles assigned to the given user
func (jc *JCloak) GetCompositeClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient, "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableClientRolesByUserID returns all available client roles to the given user
func (jc *JCloak) GetAvailableClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient, "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableClientRolesByGroupID returns all available roles to the given group
func (jc *JCloak) GetAvailableClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient, "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByGroupID returns all client roles and composite roles assigned to the given group
func (jc *JCloak) GetCompositeClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by group id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient, "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRole get a role for the given client in a realm by role name
func (jc *JCloak) GetClientRole(ctx context.Context, token, realm, idOfClient, roleName string) (*Role, error) {
	const errMessage = "could not get client role"

	var result Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "roles", roleName))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClients gets all clients in realm
func (jc *JCloak) GetClients(ctx context.Context, token, realm string, params GetClientsParams) ([]*Client, error) {
	const errMessage = "could not get clients"

	var result []*Client
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "clients"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// UserAttributeContains checks if the given attribute value is set
func UserAttributeContains(attributes map[string][]string, attribute, value string) bool {
	for _, item := range attributes[attribute] {
		if item == value {
			return true
		}
	}
	return false
}

// -----------
// Realm Roles
// -----------

// CreateRealmRole creates a role in a realm
func (jc *JCloak) CreateRealmRole(ctx context.Context, token string, realm string, role Role) (string, error) {
	const errMessage = "could not create realm role"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Post(jc.getAdminRealmURL(realm, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetRealmRole returns a role from a realm by role's name
func (jc *JCloak) GetRealmRole(ctx context.Context, token, realm, roleName string) (*Role, error) {
	const errMessage = "could not get realm role"

	var result Role

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "roles", roleName))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealmRoleByID returns a role from a realm by role's ID
func (jc *JCloak) GetRealmRoleByID(ctx context.Context, token, realm, roleID string) (*Role, error) {
	const errMessage = "could not get realm role"

	var result Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "roles-by-id", roleID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealmRoles get all roles of the given realm.
func (jc *JCloak) GetRealmRoles(ctx context.Context, token, realm string, params GetRoleParams) ([]*Role, error) {
	const errMessage = "could not get realm roles"

	var result []*Role
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetRealmRolesByUserID returns all roles assigned to the given user
func (jc *JCloak) GetRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get realm roles by user id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetRealmRolesByGroupID returns all roles assigned to the given group
func (jc *JCloak) GetRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get realm roles by group id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateRealmRole updates a role in a realm
func (jc *JCloak) UpdateRealmRole(ctx context.Context, token, realm, roleName string, role Role) error {
	const errMessage = "could not update realm role"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(jc.getAdminRealmURL(realm, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

// UpdateRealmRoleByID updates a role in a realm by role's ID
func (jc *JCloak) UpdateRealmRoleByID(ctx context.Context, token, realm, roleID string, role Role) error {
	const errMessage = "could not update realm role"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(jc.getAdminRealmURL(realm, "roles-by-id", roleID))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRole deletes a role in a realm by role's name
func (jc *JCloak) DeleteRealmRole(ctx context.Context, token, realm, roleName string) error {
	const errMessage = "could not delete realm role"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

// AddRealmRoleToUser adds realm-level role mappings
func (jc *JCloak) AddRealmRoleToUser(ctx context.Context, token, realm, userID string, roles []Role) error {
	const errMessage = "could not add realm role to user"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(jc.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRoleFromUser deletes realm-level role mappings
func (jc *JCloak) DeleteRealmRoleFromUser(ctx context.Context, token, realm, userID string, roles []Role) error {
	const errMessage = "could not delete realm role from user"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(jc.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// AddRealmRoleToGroup adds realm-level role mappings
func (jc *JCloak) AddRealmRoleToGroup(ctx context.Context, token, realm, groupID string, roles []Role) error {
	const errMessage = "could not add realm role to group"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(jc.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRoleFromGroup deletes realm-level role mappings
func (jc *JCloak) DeleteRealmRoleFromGroup(ctx context.Context, token, realm, groupID string, roles []Role) error {
	const errMessage = "could not delete realm role from group"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(jc.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// AddRealmRoleComposite adds a role to the composite.
func (jc *JCloak) AddRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error {
	const errMessage = "could not add realm role composite"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(jc.getAdminRealmURL(realm, "roles", roleName, "composites"))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRoleComposite deletes a role from the composite.
func (jc *JCloak) DeleteRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error {
	const errMessage = "could not delete realm role composite"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(jc.getAdminRealmURL(realm, "roles", roleName, "composites"))

	return checkForError(resp, err, errMessage)
}

// GetCompositeRealmRoles returns all realm composite roles associated with the given realm role
func (jc *JCloak) GetCompositeRealmRoles(ctx context.Context, token, realm, roleName string) ([]*Role, error) {
	const errMessage = "could not get composite realm roles by role"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "roles", roleName, "composites"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRolesByRoleID returns all realm composite roles associated with the given client role
func (jc *JCloak) GetCompositeRolesByRoleID(ctx context.Context, token, realm, roleID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by role id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRealmRolesByRoleID returns all realm composite roles associated with the given client role
func (jc *JCloak) GetCompositeRealmRolesByRoleID(ctx context.Context, token, realm, roleID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by role id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "roles-by-id", roleID, "composites", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRealmRolesByUserID returns all realm roles and composite roles assigned to the given user
func (jc *JCloak) GetCompositeRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm", "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRealmRolesByGroupID returns all realm roles and composite roles assigned to the given group
func (jc *JCloak) GetCompositeRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm", "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableRealmRolesByUserID returns all available realm roles to the given user
func (jc *JCloak) GetAvailableRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm", "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableRealmRolesByGroupID returns all available realm roles to the given group
func (jc *JCloak) GetAvailableRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm", "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// -----
// Realm
// -----

// GetRealm returns top-level representation of the realm
func (jc *JCloak) GetRealm(ctx context.Context, token, realm string) (*RealmRepresentation, error) {
	const errMessage = "could not get realm"

	var result RealmRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealms returns top-level representation of all realms
func (jc *JCloak) GetRealms(ctx context.Context, token string) ([]*RealmRepresentation, error) {
	const errMessage = "could not get realms"

	var result []*RealmRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(""))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateRealm creates a realm
func (jc *JCloak) CreateRealm(ctx context.Context, token string, realm RealmRepresentation) (string, error) {
	const errMessage = "could not create realm"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(&realm).
		Post(jc.getAdminRealmURL(""))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}
	return getID(resp), nil
}

// UpdateRealm updates a given realm
func (jc *JCloak) UpdateRealm(ctx context.Context, token string, realm RealmRepresentation) error {
	const errMessage = "could not update realm"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(realm).
		Put(jc.getAdminRealmURL(PString(realm.Realm)))

	return checkForError(resp, err, errMessage)
}

// DeleteRealm removes a realm
func (jc *JCloak) DeleteRealm(ctx context.Context, token, realm string) error {
	const errMessage = "could not delete realm"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm))

	return checkForError(resp, err, errMessage)
}

// ClearRealmCache clears realm cache
func (jc *JCloak) ClearRealmCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear realm cache"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Post(jc.getAdminRealmURL(realm, "clear-realm-cache"))

	return checkForError(resp, err, errMessage)
}

// ClearUserCache clears realm cache
func (jc *JCloak) ClearUserCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear user cache"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Post(jc.getAdminRealmURL(realm, "clear-user-cache"))

	return checkForError(resp, err, errMessage)
}

// ClearKeysCache clears realm cache
func (jc *JCloak) ClearKeysCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear keys cache"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Post(jc.getAdminRealmURL(realm, "clear-keys-cache"))

	return checkForError(resp, err, errMessage)
}

// GetAuthenticationFlows get all authentication flows from a realm
func (jc *JCloak) GetAuthenticationFlows(ctx context.Context, token, realm string) ([]*AuthenticationFlowRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result []*AuthenticationFlowRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "authentication", "flows"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

// CreateAuthenticationFlow creates a new Authentication flow in a realm
func (jc *JCloak) CreateAuthenticationFlow(ctx context.Context, token, realm string, flow AuthenticationFlowRepresentation) error {
	const errMessage = "could not create authentication flows"
	var result []*AuthenticationFlowRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).SetBody(flow).
		Post(jc.getAdminRealmURL(realm, "authentication", "flows"))

	return checkForError(resp, err, errMessage)
}

// DeleteAuthenticationFlow deletes a flow in a realm with the given ID
func (jc *JCloak) DeleteAuthenticationFlow(ctx context.Context, token, realm, flowID string) error {
	const errMessage = "could not delete authentication flows"
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "authentication", "flows", flowID))

	return checkForError(resp, err, errMessage)
}

// GetAuthenticationExecutions retrieves all executions of a given flow
func (jc *JCloak) GetAuthenticationExecutions(ctx context.Context, token, realm, flow string) ([]*ModifyAuthenticationExecutionRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result []*ModifyAuthenticationExecutionRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "authentication", "flows", flow, "executions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

// CreateAuthenticationExecution creates a new execution for the given flow name in the given realm
func (jc *JCloak) CreateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution CreateAuthenticationExecutionRepresentation) error {
	const errMessage = "could not create authentication execution"
	resp, err := jc.getRequestWithBearerAuth(ctx, token).SetBody(execution).
		Post(jc.getAdminRealmURL(realm, "authentication", "flows", flow, "executions", "execution"))

	return checkForError(resp, err, errMessage)
}

// UpdateAuthenticationExecution updates an authentication execution for the given flow in the given realm
func (jc *JCloak) UpdateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution ModifyAuthenticationExecutionRepresentation) error {
	const errMessage = "could not update authentication execution"
	resp, err := jc.getRequestWithBearerAuth(ctx, token).SetBody(execution).
		Put(jc.getAdminRealmURL(realm, "authentication", "flows", flow, "executions"))

	return checkForError(resp, err, errMessage)
}

// DeleteAuthenticationExecution delete a single execution with the given ID
func (jc *JCloak) DeleteAuthenticationExecution(ctx context.Context, token, realm, executionID string) error {
	const errMessage = "could not delete authentication execution"
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "authentication", "executions", executionID))

	return checkForError(resp, err, errMessage)
}

// CreateAuthenticationExecutionFlow creates a new execution for the given flow name in the given realm
func (jc *JCloak) CreateAuthenticationExecutionFlow(ctx context.Context, token, realm, flow string, executionFlow CreateAuthenticationExecutionFlowRepresentation) error {
	const errMessage = "could not create authentication execution flow"
	resp, err := jc.getRequestWithBearerAuth(ctx, token).SetBody(executionFlow).
		Post(jc.getAdminRealmURL(realm, "authentication", "flows", flow, "executions", "flow"))

	return checkForError(resp, err, errMessage)
}

// -----
// Users
// -----

// CreateUser creates the given user in the given realm and returns it's userID
// Note: Keycloak has not documented what members of the User object are actually being accepted, when creating a user.
// Things like RealmRoles must be attached using followup calls to the respective functions.
func (jc *JCloak) CreateUser(ctx context.Context, token, realm string, user User) (string, error) {
	const errMessage = "could not create user"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(user).
		Post(jc.getAdminRealmURL(realm, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// DeleteUser delete a given user
func (jc *JCloak) DeleteUser(ctx context.Context, token, realm, userID string) error {
	const errMessage = "could not delete user"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "users", userID))

	return checkForError(resp, err, errMessage)
}

// GetUserByID fetches a user from the given realm with the given userID
func (jc *JCloak) GetUserByID(ctx context.Context, accessToken, realm, userID string) (*User, error) {
	const errMessage = "could not get user by id"

	if userID == "" {
		return nil, errors.Wrap(errors.New("userID shall not be empty"), errMessage)
	}

	var result User
	resp, err := jc.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "users", userID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetUserCount gets the user count in the realm
func (jc *JCloak) GetUserCount(ctx context.Context, token string, realm string, params GetUsersParams) (int, error) {
	const errMessage = "could not get user count"

	var result int
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return 0, errors.Wrap(err, errMessage)
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "users", "count"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return -1, errors.Wrap(err, errMessage)
	}

	return result, nil
}

// GetUserGroups get all groups for user
func (jc *JCloak) GetUserGroups(ctx context.Context, token, realm, userID string, params GetGroupsParams) ([]*Group, error) {
	const errMessage = "could not get user groups"

	var result []*Group
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "users", userID, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetUsers get all users in realm
func (jc *JCloak) GetUsers(ctx context.Context, token, realm string, params GetUsersParams) ([]*User, error) {
	const errMessage = "could not get users"

	var result []*User
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetUsersByRoleName returns all users have a given role
func (jc *JCloak) GetUsersByRoleName(ctx context.Context, token, realm, roleName string) ([]*User, error) {
	const errMessage = "could not get users by role name"

	var result []*User
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "roles", roleName, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetUsersByClientRoleName returns all users have a given client role
func (jc *JCloak) GetUsersByClientRoleName(ctx context.Context, token, realm, idOfClient, roleName string, params GetUsersByRoleParams) ([]*User, error) {
	const errMessage = "could not get users by client role name"

	var result []*User
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "roles", roleName, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// SetPassword sets a new password for the user with the given id. Needs elevated privileges
func (jc *JCloak) SetPassword(ctx context.Context, token, userID, realm, password string, temporary bool) error {
	const errMessage = "could not set password"

	requestBody := SetPasswordRequest{Password: &password, Temporary: &temporary, Type: StringP("password")}
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(requestBody).
		Put(jc.getAdminRealmURL(realm, "users", userID, "reset-password"))

	return checkForError(resp, err, errMessage)
}

// UpdateUser updates a given user
func (jc *JCloak) UpdateUser(ctx context.Context, token, realm string, user User) error {
	const errMessage = "could not update user"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(user).
		Put(jc.getAdminRealmURL(realm, "users", PString(user.ID)))

	return checkForError(resp, err, errMessage)
}

// AddUserToGroup puts given user to given group
func (jc *JCloak) AddUserToGroup(ctx context.Context, token, realm, userID, groupID string) error {
	const errMessage = "could not add user to group"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Put(jc.getAdminRealmURL(realm, "users", userID, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// DeleteUserFromGroup deletes given user from given group
func (jc *JCloak) DeleteUserFromGroup(ctx context.Context, token, realm, userID, groupID string) error {
	const errMessage = "could not delete user from group"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "users", userID, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// GetUserSessions returns user sessions associated with the user
func (jc *JCloak) GetUserSessions(ctx context.Context, token, realm, userID string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get user sessions"

	var res []*UserSessionRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(jc.getAdminRealmURL(realm, "users", userID, "sessions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// GetUserOfflineSessionsForClient returns offline sessions associated with the user and client
func (jc *JCloak) GetUserOfflineSessionsForClient(ctx context.Context, token, realm, userID, idOfClient string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get user offline sessions for client"

	var res []*UserSessionRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(jc.getAdminRealmURL(realm, "users", userID, "offline-sessions", idOfClient))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// AddClientRolesToUser adds client-level role mappings
func (jc *JCloak) AddClientRolesToUser(ctx context.Context, token, realm, idOfClient, userID string, roles []Role) error {
	const errMessage = "could not add client role to user"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(jc.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// AddClientRoleToUser adds client-level role mappings
//
// Deprecated: replaced by AddClientRolesToUser
func (jc *JCloak) AddClientRoleToUser(ctx context.Context, token, realm, idOfClient, userID string, roles []Role) error {
	return jc.AddClientRolesToUser(ctx, token, realm, idOfClient, userID, roles)
}

// AddClientRolesToGroup adds a client role to the group
func (jc *JCloak) AddClientRolesToGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error {
	const errMessage = "could not add client role to group"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(jc.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// AddClientRoleToGroup adds a client role to the group
//
// Deprecated: replaced by AddClientRolesToGroup
func (jc *JCloak) AddClientRoleToGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error {
	return jc.AddClientRolesToGroup(ctx, token, realm, idOfClient, groupID, roles)
}

// DeleteClientRolesFromUser adds client-level role mappings
func (jc *JCloak) DeleteClientRolesFromUser(ctx context.Context, token, realm, idOfClient, userID string, roles []Role) error {
	const errMessage = "could not delete client role from user"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(jc.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRoleFromUser adds client-level role mappings
//
// Deprecated: replaced by DeleteClientRolesFrom
func (jc *JCloak) DeleteClientRoleFromUser(ctx context.Context, token, realm, idOfClient, userID string, roles []Role) error {
	return jc.DeleteClientRolesFromUser(ctx, token, realm, idOfClient, userID, roles)
}

// DeleteClientRoleFromGroup removes a client role from from the group
func (jc *JCloak) DeleteClientRoleFromGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error {
	const errMessage = "could not client role from group"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(jc.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// AddClientRoleComposite adds roles as composite
func (jc *JCloak) AddClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error {
	const errMessage = "could not add client role composite"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(jc.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRoleComposite deletes composites from a role
func (jc *JCloak) DeleteClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error {
	const errMessage = "could not delete client role composite"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(jc.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	return checkForError(resp, err, errMessage)
}

// GetUserFederatedIdentities gets all user federated identities
func (jc *JCloak) GetUserFederatedIdentities(ctx context.Context, token, realm, userID string) ([]*FederatedIdentityRepresentation, error) {
	const errMessage = "could not get user federated identities"

	var res []*FederatedIdentityRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(jc.getAdminRealmURL(realm, "users", userID, "federated-identity"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, err
}

// CreateUserFederatedIdentity creates an user federated identity
func (jc *JCloak) CreateUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string, federatedIdentityRep FederatedIdentityRepresentation) error {
	const errMessage = "could not create user federeated identity"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(federatedIdentityRep).
		Post(jc.getAdminRealmURL(realm, "users", userID, "federated-identity", providerID))

	return checkForError(resp, err, errMessage)
}

// DeleteUserFederatedIdentity deletes an user federated identity
func (jc *JCloak) DeleteUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string) error {
	const errMessage = "could not delete user federeated identity"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "users", userID, "federated-identity", providerID))

	return checkForError(resp, err, errMessage)
}

// ------------------
// Identity Providers
// ------------------

// CreateIdentityProvider creates an identity provider in a realm
func (jc *JCloak) CreateIdentityProvider(ctx context.Context, token string, realm string, providerRep IdentityProviderRepresentation) (string, error) {
	const errMessage = "could not create identity provider"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(providerRep).
		Post(jc.getAdminRealmURL(realm, "identity-provider", "instances"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetIdentityProviders returns list of identity providers in a realm
func (jc *JCloak) GetIdentityProviders(ctx context.Context, token, realm string) ([]*IdentityProviderRepresentation, error) {
	const errMessage = "could not get identity providers"

	var result []*IdentityProviderRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "identity-provider", "instances"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetIdentityProvider gets the identity provider in a realm
func (jc *JCloak) GetIdentityProvider(ctx context.Context, token, realm, alias string) (*IdentityProviderRepresentation, error) {
	const errMessage = "could not get identity provider"

	var result IdentityProviderRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateIdentityProvider updates the identity provider in a realm
func (jc *JCloak) UpdateIdentityProvider(ctx context.Context, token, realm, alias string, providerRep IdentityProviderRepresentation) error {
	const errMessage = "could not update identity provider"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(providerRep).
		Put(jc.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	return checkForError(resp, err, errMessage)
}

// DeleteIdentityProvider deletes the identity provider in a realm
func (jc *JCloak) DeleteIdentityProvider(ctx context.Context, token, realm, alias string) error {
	const errMessage = "could not delete identity provider"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	return checkForError(resp, err, errMessage)
}

// ExportIDPPublicBrokerConfig exports the broker config for a given alias
func (jc *JCloak) ExportIDPPublicBrokerConfig(ctx context.Context, token, realm, alias string) (*string, error) {
	const errMessage = "could not get public identity provider configuration"

	resp, err := jc.getRequestWithBearerAuthXMLHeader(ctx, token).
		Get(jc.getAdminRealmURL(realm, "identity-provider", "instances", alias, "export"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	result := resp.String()
	return &result, nil
}

// ImportIdentityProviderConfig parses and returns the identity provider config at a given URL
func (jc *JCloak) ImportIdentityProviderConfig(ctx context.Context, token, realm, fromURL, providerID string) (map[string]string, error) {
	const errMessage = "could not import config"

	result := make(map[string]string)
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(map[string]string{
			"fromUrl":    fromURL,
			"providerId": providerID,
		}).
		Post(jc.getAdminRealmURL(realm, "identity-provider", "import-config"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// ImportIdentityProviderConfigFromFile parses and returns the identity provider config from a given file
func (jc *JCloak) ImportIdentityProviderConfigFromFile(ctx context.Context, token, realm, providerID, fileName string, fileBody io.Reader) (map[string]string, error) {
	const errMessage = "could not import config"

	result := make(map[string]string)
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetFileReader("file", fileName, fileBody).
		SetFormData(map[string]string{
			"providerId": providerID,
		}).
		Post(jc.getAdminRealmURL(realm, "identity-provider", "import-config"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateIdentityProviderMapper creates an instance of an identity provider mapper associated with the given alias
func (jc *JCloak) CreateIdentityProviderMapper(ctx context.Context, token, realm, alias string, mapper IdentityProviderMapper) (string, error) {
	const errMessage = "could not create mapper for identity provider"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Post(jc.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetIdentityProviderMapper gets the mapper by id for the given identity provider alias in a realm
func (jc *JCloak) GetIdentityProviderMapper(ctx context.Context, token string, realm string, alias string, mapperID string) (*IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mapper"

	result := IdentityProviderMapper{}
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteIdentityProviderMapper deletes an instance of an identity provider mapper associated with the given alias and mapper ID
func (jc *JCloak) DeleteIdentityProviderMapper(ctx context.Context, token, realm, alias, mapperID string) error {
	const errMessage = "could not delete mapper for identity provider"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	return checkForError(resp, err, errMessage)
}

// GetIdentityProviderMappers returns list of mappers associated with an identity provider
func (jc *JCloak) GetIdentityProviderMappers(ctx context.Context, token, realm, alias string) ([]*IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mappers"

	var result []*IdentityProviderMapper
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetIdentityProviderMapperByID gets the mapper of an identity provider
func (jc *JCloak) GetIdentityProviderMapperByID(ctx context.Context, token, realm, alias, mapperID string) (*IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mappers"

	var result IdentityProviderMapper
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateIdentityProviderMapper updates mapper of an identity provider
func (jc *JCloak) UpdateIdentityProviderMapper(ctx context.Context, token, realm, alias string, mapper IdentityProviderMapper) error {
	const errMessage = "could not update identity provider mapper"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Put(jc.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", PString(mapper.ID)))

	return checkForError(resp, err, errMessage)
}

// ------------------
// Protection API
// ------------------

// GetResource returns a client's resource with the given id, using access token from admin
func (jc *JCloak) GetResource(ctx context.Context, token, realm, idOfClient, resourceID string) (*ResourceRepresentation, error) {
	const errMessage = "could not get resource"

	var result ResourceRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", resourceID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResourceClient returns a client's resource with the given id, using access token from client
func (jc *JCloak) GetResourceClient(ctx context.Context, token, realm, resourceID string) (*ResourceRepresentation, error) {
	const errMessage = "could not get resource"

	var result ResourceRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getRealmURL(realm, "authz", "protection", "resource_set", resourceID))

	// http://${host}:${port}/auth/realms/${realm_name}/authz/protection/resource_set/{resource_id}

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResources returns resources associated with the client, using access token from admin
func (jc *JCloak) GetResources(ctx context.Context, token, realm, idOfClient string, params GetResourceParams) ([]*ResourceRepresentation, error) {
	const errMessage = "could not get resources"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourceRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetResourcesClient returns resources associated with the client, using access token from client
func (jc *JCloak) GetResourcesClient(ctx context.Context, token, realm string, params GetResourceParams) ([]*ResourceRepresentation, error) {
	const errMessage = "could not get resources"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourceRepresentation
	var resourceIDs []string
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&resourceIDs).
		SetQueryParams(queryParams).
		Get(jc.getRealmURL(realm, "authz", "protection", "resource_set"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	for _, resourceID := range resourceIDs {
		resource, err := jc.GetResourceClient(ctx, token, realm, resourceID)
		if err == nil {
			result = append(result, resource)
		}
	}

	return result, nil
}

// UpdateResource updates a resource associated with the client, using access token from admin
func (jc *JCloak) UpdateResource(ctx context.Context, token, realm, idOfClient string, resource ResourceRepresentation) error {
	const errMessage = "could not update resource"

	if NilOrEmpty(resource.ID) {
		return errors.New("ID of a resource required")
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(resource).
		Put(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", *(resource.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateResourceClient updates a resource associated with the client, using access token from client
func (jc *JCloak) UpdateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) error {
	const errMessage = "could not update resource"

	if NilOrEmpty(resource.ID) {
		return errors.New("ID of a resource required")
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(resource).
		Put(jc.getRealmURL(realm, "authz", "protection", "resource_set", *(resource.ID)))

	return checkForError(resp, err, errMessage)
}

// CreateResource creates a resource associated with the client, using access token from admin
func (jc *JCloak) CreateResource(ctx context.Context, token, realm string, idOfClient string, resource ResourceRepresentation) (*ResourceRepresentation, error) {
	const errMessage = "could not create resource"

	var result ResourceRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(resource).
		Post(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateResourceClient creates a resource associated with the client, using access token from client
func (jc *JCloak) CreateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) (*ResourceRepresentation, error) {
	const errMessage = "could not create resource"

	var result ResourceRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(resource).
		Post(jc.getRealmURL(realm, "authz", "protection", "resource_set"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteResource deletes a resource associated with the client (using an admin token)
func (jc *JCloak) DeleteResource(ctx context.Context, token, realm, idOfClient, resourceID string) error {
	const errMessage = "could not delete resource"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", resourceID))

	return checkForError(resp, err, errMessage)
}

// DeleteResourceClient deletes a resource associated with the client (using a client token)
func (jc *JCloak) DeleteResourceClient(ctx context.Context, token, realm, resourceID string) error {
	const errMessage = "could not delete resource"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getRealmURL(realm, "authz", "protection", "resource_set", resourceID))

	return checkForError(resp, err, errMessage)
}

// GetScope returns a client's scope with the given id
func (jc *JCloak) GetScope(ctx context.Context, token, realm, idOfClient, scopeID string) (*ScopeRepresentation, error) {
	const errMessage = "could not get scope"

	var result ScopeRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", scopeID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetScopes returns scopes associated with the client
func (jc *JCloak) GetScopes(ctx context.Context, token, realm, idOfClient string, params GetScopeParams) ([]*ScopeRepresentation, error) {
	const errMessage = "could not get scopes"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}
	var result []*ScopeRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateScope creates a scope associated with the client
func (jc *JCloak) CreateScope(ctx context.Context, token, realm, idOfClient string, scope ScopeRepresentation) (*ScopeRepresentation, error) {
	const errMessage = "could not create scope"

	var result ScopeRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(scope).
		Post(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateScope updates a scope associated with the client
func (jc *JCloak) UpdateScope(ctx context.Context, token, realm, idOfClient string, scope ScopeRepresentation) error {
	const errMessage = "could not update scope"

	if NilOrEmpty(scope.ID) {
		return errors.New("ID of a scope required")
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Put(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", *(scope.ID)))

	return checkForError(resp, err, errMessage)
}

// DeleteScope deletes a scope associated with the client
func (jc *JCloak) DeleteScope(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not delete scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetPolicy returns a client's policy with the given id
func (jc *JCloak) GetPolicy(ctx context.Context, token, realm, idOfClient, policyID string) (*PolicyRepresentation, error) {
	const errMessage = "could not get policy"

	var result PolicyRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetPolicies returns policies associated with the client
func (jc *JCloak) GetPolicies(ctx context.Context, token, realm, idOfClient string, params GetPolicyParams) ([]*PolicyRepresentation, error) {
	const errMessage = "could not get policies"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	path := []string{"clients", idOfClient, "authz", "resource-server", "policy"}
	if !NilOrEmpty(params.Type) {
		path = append(path, *params.Type)
	}

	var result []*PolicyRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, path...))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreatePolicy creates a policy associated with the client
func (jc *JCloak) CreatePolicy(ctx context.Context, token, realm, idOfClient string, policy PolicyRepresentation) (*PolicyRepresentation, error) {
	const errMessage = "could not create policy"

	if NilOrEmpty(policy.Type) {
		return nil, errors.New("type of a policy required")
	}

	var result PolicyRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(policy).
		Post(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", *(policy.Type)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdatePolicy updates a policy associated with the client
func (jc *JCloak) UpdatePolicy(ctx context.Context, token, realm, idOfClient string, policy PolicyRepresentation) error {
	const errMessage = "could not update policy"

	if NilOrEmpty(policy.ID) {
		return errors.New("ID of a policy required")
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(policy).
		Put(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", *(policy.Type), *(policy.ID)))

	return checkForError(resp, err, errMessage)
}

// DeletePolicy deletes a policy associated with the client
func (jc *JCloak) DeletePolicy(ctx context.Context, token, realm, idOfClient, policyID string) error {
	const errMessage = "could not delete policy"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID))

	return checkForError(resp, err, errMessage)
}

// GetAuthorizationPolicyAssociatedPolicies returns a client's associated policies of specific policy with the given policy id, using access token from admin
func (jc *JCloak) GetAuthorizationPolicyAssociatedPolicies(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyRepresentation, error) {
	const errMessage = "could not get policy associated policies"

	var result []*PolicyRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "associatedPolicies"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAuthorizationPolicyResources returns a client's resources of specific policy with the given policy id, using access token from admin
func (jc *JCloak) GetAuthorizationPolicyResources(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyResourceRepresentation, error) {
	const errMessage = "could not get policy resources"

	var result []*PolicyResourceRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "resources"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAuthorizationPolicyScopes returns a client's scopes of specific policy with the given policy id, using access token from admin
func (jc *JCloak) GetAuthorizationPolicyScopes(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyScopeRepresentation, error) {
	const errMessage = "could not get policy scopes"

	var result []*PolicyScopeRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetResourcePolicy updates a permission for a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (jc *JCloak) GetResourcePolicy(ctx context.Context, token, realm, permissionID string) (*ResourcePolicyRepresentation, error) {
	const errMessage = "could not get resource policy"

	var result ResourcePolicyRepresentation
	resp, err := jc.getRequestWithBearerAuthNoCache(ctx, token).
		SetResult(&result).
		Get(jc.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResourcePolicies returns resources associated with the client, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (jc *JCloak) GetResourcePolicies(ctx context.Context, token, realm string, params GetResourcePoliciesParams) ([]*ResourcePolicyRepresentation, error) {
	const errMessage = "could not get resource policies"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourcePolicyRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getRealmURL(realm, "authz", "protection", "uma-policy"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateResourcePolicy associates a permission with a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (jc *JCloak) CreateResourcePolicy(ctx context.Context, token, realm, resourceID string, policy ResourcePolicyRepresentation) (*ResourcePolicyRepresentation, error) {
	const errMessage = "could not create resource policy"

	var result ResourcePolicyRepresentation
	resp, err := jc.getRequestWithBearerAuthNoCache(ctx, token).
		SetResult(&result).
		SetBody(policy).
		Post(jc.getRealmURL(realm, "authz", "protection", "uma-policy", resourceID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateResourcePolicy updates a permission for a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (jc *JCloak) UpdateResourcePolicy(ctx context.Context, token, realm, permissionID string, policy ResourcePolicyRepresentation) error {
	const errMessage = "could not update resource policy"

	resp, err := jc.getRequestWithBearerAuthNoCache(ctx, token).
		SetBody(policy).
		Put(jc.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	return checkForError(resp, err, errMessage)
}

// DeleteResourcePolicy deletes a permission for a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (jc *JCloak) DeleteResourcePolicy(ctx context.Context, token, realm, permissionID string) error {
	const errMessage = "could not  delete resource policy"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	return checkForError(resp, err, errMessage)
}

// GetPermission returns a client's permission with the given id
func (jc *JCloak) GetPermission(ctx context.Context, token, realm, idOfClient, permissionID string) (*PermissionRepresentation, error) {
	const errMessage = "could not get permission"

	var result PermissionRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetDependentPermissions returns a client's permission with the given policy id
func (jc *JCloak) GetDependentPermissions(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PermissionRepresentation, error) {
	const errMessage = "could not get permission"

	var result []*PermissionRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "dependentPolicies"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissionResources returns a client's resource attached for the given permission id
func (jc *JCloak) GetPermissionResources(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*PermissionResource, error) {
	const errMessage = "could not get permission resource"

	var result []*PermissionResource
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID, "resources"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissionScopes returns a client's scopes configured for the given permission id
func (jc *JCloak) GetPermissionScopes(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*PermissionScope, error) {
	const errMessage = "could not get permission scopes"

	var result []*PermissionScope
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID, "scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissions returns permissions associated with the client
func (jc *JCloak) GetPermissions(ctx context.Context, token, realm, idOfClient string, params GetPermissionParams) ([]*PermissionRepresentation, error) {
	const errMessage = "could not get permissions"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	path := []string{"clients", idOfClient, "authz", "resource-server", "permission"}
	if !NilOrEmpty(params.Type) {
		path = append(path, *params.Type)
	}

	var result []*PermissionRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, path...))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// checkPermissionTicketParams checks that mandatory fields are present
func checkPermissionTicketParams(permissions []CreatePermissionTicketParams) error {
	if len(permissions) == 0 {
		return errors.New("at least one permission ticket must be requested")
	}

	for _, pt := range permissions {

		if NilOrEmpty(pt.ResourceID) {
			return errors.New("resourceID required for permission ticket")
		}
		if NilOrEmptyArray(pt.ResourceScopes) {
			return errors.New("at least one resourceScope required for permission ticket")
		}
	}

	return nil
}

// CreatePermissionTicket creates a permission ticket, using access token from client
func (jc *JCloak) CreatePermissionTicket(ctx context.Context, token, realm string, permissions []CreatePermissionTicketParams) (*PermissionTicketResponseRepresentation, error) {
	const errMessage = "could not create permission ticket"

	err := checkPermissionTicketParams(permissions)
	if err != nil {
		return nil, err
	}

	var result PermissionTicketResponseRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permissions).
		Post(jc.getRealmURL(realm, "authz", "protection", "permission"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// checkPermissionGrantParams checks for mandatory fields
func checkPermissionGrantParams(permission PermissionGrantParams) error {
	if NilOrEmpty(permission.RequesterID) {
		return errors.New("requesterID required to grant user permission")
	}
	if NilOrEmpty(permission.ResourceID) {
		return errors.New("resourceID required to grant user permission")
	}
	if NilOrEmpty(permission.ScopeName) {
		return errors.New("scopeName required to grant user permission")
	}

	return nil
}

// GrantUserPermission lets resource owner grant permission for specific resource ID to specific user ID
func (jc *JCloak) GrantUserPermission(ctx context.Context, token, realm string, permission PermissionGrantParams) (*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not grant user permission"

	err := checkPermissionGrantParams(permission)
	if err != nil {
		return nil, err
	}

	permission.Granted = BoolP(true)

	var result PermissionGrantResponseRepresentation

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Post(jc.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// checkPermissionUpdateParams
func checkPermissionUpdateParams(permission PermissionGrantParams) error {
	err := checkPermissionGrantParams(permission)
	if err != nil {
		return err
	}

	if permission.Granted == nil {
		return errors.New("granted required to update user permission")
	}
	return nil
}

// UpdateUserPermission updates user permissions.
func (jc *JCloak) UpdateUserPermission(ctx context.Context, token, realm string, permission PermissionGrantParams) (*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not update user permission"

	err := checkPermissionUpdateParams(permission)
	if err != nil {
		return nil, err
	}

	var result PermissionGrantResponseRepresentation

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Put(jc.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	if resp.StatusCode() == http.StatusNoContent { // permission updated to 'not granted' removes permission
		return nil, nil
	}

	return &result, nil
}

// GetUserPermissions gets granted permissions according query parameters
func (jc *JCloak) GetUserPermissions(ctx context.Context, token, realm string, params GetUserPermissionParams) ([]*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not get user permissions"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*PermissionGrantResponseRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteUserPermission revokes permissions according query parameters
func (jc *JCloak) DeleteUserPermission(ctx context.Context, token, realm, ticketID string) error {
	const errMessage = "could not delete user permission"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getRealmURL(realm, "authz", "protection", "permission", "ticket", ticketID))

	return checkForError(resp, err, errMessage)
}

// CreatePermission creates a permission associated with the client
func (jc *JCloak) CreatePermission(ctx context.Context, token, realm, idOfClient string, permission PermissionRepresentation) (*PermissionRepresentation, error) {
	const errMessage = "could not create permission"

	if NilOrEmpty(permission.Type) {
		return nil, errors.New("type of a permission required")
	}

	var result PermissionRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Post(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", *(permission.Type)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdatePermission updates a permission associated with the client
func (jc *JCloak) UpdatePermission(ctx context.Context, token, realm, idOfClient string, permission PermissionRepresentation) error {
	const errMessage = "could not update permission"

	if NilOrEmpty(permission.ID) {
		return errors.New("ID of a permission required")
	}
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(permission).
		Put(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", *permission.Type, *permission.ID))

	return checkForError(resp, err, errMessage)
}

// DeletePermission deletes a policy associated with the client
func (jc *JCloak) DeletePermission(ctx context.Context, token, realm, idOfClient, permissionID string) error {
	const errMessage = "could not delete permission"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID))

	return checkForError(resp, err, errMessage)
}

// ---------------
// Credentials API
// ---------------

// GetCredentialRegistrators returns credentials registrators
func (jc *JCloak) GetCredentialRegistrators(ctx context.Context, token, realm string) ([]string, error) {
	const errMessage = "could not get user credential registrators"

	var result []string
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "credential-registrators"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetConfiguredUserStorageCredentialTypes returns credential types, which are provided by the user storage where user is stored
func (jc *JCloak) GetConfiguredUserStorageCredentialTypes(ctx context.Context, token, realm, userID string) ([]string, error) {
	const errMessage = "could not get user credential registrators"

	var result []string
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "users", userID, "configured-user-storage-credential-types"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCredentials returns credentials available for a given user
func (jc *JCloak) GetCredentials(ctx context.Context, token, realm, userID string) ([]*CredentialRepresentation, error) {
	const errMessage = "could not get user credentials"

	var result []*CredentialRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "users", userID, "credentials"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteCredentials deletes the given credential for a given user
func (jc *JCloak) DeleteCredentials(ctx context.Context, token, realm, userID, credentialID string) error {
	const errMessage = "could not delete user credentials"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "users", userID, "credentials", credentialID))

	return checkForError(resp, err, errMessage)
}

// UpdateCredentialUserLabel updates label for the given credential for the given user
func (jc *JCloak) UpdateCredentialUserLabel(ctx context.Context, token, realm, userID, credentialID, userLabel string) error {
	const errMessage = "could not update credential label for a user"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetHeader("Content-Type", "text/plain").
		SetBody(userLabel).
		Put(jc.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "userLabel"))

	return checkForError(resp, err, errMessage)
}

// DisableAllCredentialsByType disables all credentials for a user of a specific type
func (jc *JCloak) DisableAllCredentialsByType(ctx context.Context, token, realm, userID string, types []string) error {
	const errMessage = "could not update disable credentials"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(types).
		Put(jc.getAdminRealmURL(realm, "users", userID, "disable-credential-types"))

	return checkForError(resp, err, errMessage)
}

// MoveCredentialBehind move a credential to a position behind another credential
func (jc *JCloak) MoveCredentialBehind(ctx context.Context, token, realm, userID, credentialID, newPreviousCredentialID string) error {
	const errMessage = "could not move credential"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Post(jc.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "moveAfter", newPreviousCredentialID))

	return checkForError(resp, err, errMessage)
}

// MoveCredentialToFirst move a credential to a first position in the credentials list of the user
func (jc *JCloak) MoveCredentialToFirst(ctx context.Context, token, realm, userID, credentialID string) error {
	const errMessage = "could not move credential"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Post(jc.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "moveToFirst"))

	return checkForError(resp, err, errMessage)
}

// GetEvents returns events
func (jc *JCloak) GetEvents(ctx context.Context, token string, realm string, params GetEventsParams) ([]*EventRepresentation, error) {
	const errMessage = "could not get events"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	var result []*EventRepresentation
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(jc.getAdminRealmURL(realm, "events"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopesScopeMappingsRealmRolesAvailable returns realm-level roles that are available to attach to this client scope
func (jc *JCloak) GetClientScopesScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, clientScopeID string) ([]*Role, error) {
	const errMessage = "could not get available realm-level roles with the client-scope"

	var result []*Role

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm", "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopesScopeMappingsRealmRoles returns roles associated with a client-scope
func (jc *JCloak) GetClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, clientScopeID string) ([]*Role, error) {
	const errMessage = "could not get realm-level roles with the client-scope"

	var result []*Role

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteClientScopesScopeMappingsRealmRoles deletes realm-level roles from the client-scope
func (jc *JCloak) DeleteClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, clientScopeID string, roles []Role) error {
	const errMessage = "could not delete realm-level roles from the client-scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(jc.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// CreateClientScopesScopeMappingsRealmRoles creates realm-level roles to the client scope
func (jc *JCloak) CreateClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, clientScopeID string, roles []Role) error {
	const errMessage = "could not create realm-level roles to the client-scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(jc.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// RegisterRequiredAction creates a required action for a given realm
func (jc *JCloak) RegisterRequiredAction(ctx context.Context, token string, realm string, requiredAction RequiredActionProviderRepresentation) error {
	const errMessage = "could not create required action"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(requiredAction).
		Post(jc.getAdminRealmURL(realm, "authentication", "register-required-action"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return err
	}

	return err
}

// GetRequiredActions gets a list of required actions for a given realm
func (jc *JCloak) GetRequiredActions(ctx context.Context, token string, realm string) ([]*RequiredActionProviderRepresentation, error) {
	const errMessage = "could not get required actions"
	var result []*RequiredActionProviderRepresentation

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "authentication", "required-actions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, err
}

// GetRequiredAction gets a required action for a given realm
func (jc *JCloak) GetRequiredAction(ctx context.Context, token string, realm string, alias string) (*RequiredActionProviderRepresentation, error) {
	const errMessage = "could not get required action"
	var result RequiredActionProviderRepresentation

	if alias == "" {
		return nil, errors.New("alias is required for getting a required action")
	}

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "authentication", "required-actions", alias))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, err
}

// UpdateRequiredAction updates a required action for a given realm
func (jc *JCloak) UpdateRequiredAction(ctx context.Context, token string, realm string, requiredAction RequiredActionProviderRepresentation) error {
	const errMessage = "could not update required action"

	if NilOrEmpty(requiredAction.ProviderID) {
		return errors.New("providerId is required for updating a required action")
	}
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(requiredAction).
		Put(jc.getAdminRealmURL(realm, "authentication", "required-actions", *requiredAction.ProviderID))

	return checkForError(resp, err, errMessage)
}

// DeleteRequiredAction updates a required action for a given realm
func (jc *JCloak) DeleteRequiredAction(ctx context.Context, token string, realm string, alias string) error {
	const errMessage = "could not delete required action"

	if alias == "" {
		return errors.New("alias is required for deleting a required action")
	}
	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		Delete(jc.getAdminRealmURL(realm, "authentication", "required-actions", alias))

	if err := checkForError(resp, err, errMessage); err != nil {
		return err
	}

	return err
}

// CreateClientScopesScopeMappingsClientRoles attaches a client role to a client scope (not client's scope)
func (jc *JCloak) CreateClientScopesScopeMappingsClientRoles(
	ctx context.Context, token, realm, idOfClientScope, idOfClient string, roles []Role,
) error {
	const errMessage = "could not create client-level roles to the client-scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(jc.getAdminRealmURL(realm, "client-scopes", idOfClientScope, "scope-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// GetClientScopesScopeMappingsClientRolesAvailable returns available (i.e. not attached via
// CreateClientScopesScopeMappingsClientRoles) client roles for a specific client, for a client scope
// (not client's scope).
func (jc *JCloak) GetClientScopesScopeMappingsClientRolesAvailable(ctx context.Context, token, realm, idOfClientScope, idOfClient string) ([]*Role, error) {
	const errMessage = "could not get available client-level roles with the client-scope"

	var result []*Role

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "client-scopes", idOfClientScope, "scope-mappings", "clients", idOfClient, "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopesScopeMappingsClientRoles returns attached client roles for a specific client, for a client scope
// (not client's scope).
func (jc *JCloak) GetClientScopesScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClientScope, idOfClient string) ([]*Role, error) {
	const errMessage = "could not get client-level roles with the client-scope"

	var result []*Role

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(jc.getAdminRealmURL(realm, "client-scopes", idOfClientScope, "scope-mappings", "clients", idOfClient))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteClientScopesScopeMappingsClientRoles removes attachment of client roles from a client scope
// (not client's scope).
func (jc *JCloak) DeleteClientScopesScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClientScope, idOfClient string, roles []Role) error {
	const errMessage = "could not delete client-level roles from the client-scope"

	resp, err := jc.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(jc.getAdminRealmURL(realm, "client-scopes", idOfClientScope, "scope-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}
