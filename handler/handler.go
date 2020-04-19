package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// Handler represents an oauth callback server.
type Handler struct {
	shutdownChannel   chan error
	doneMessage       string
	port              int
	scope             string
	state             string
	verifier          string
	challenge         string
	hydraBaseUrl      string
	clientID          string
	redirectURI       string
	logoutRedirectURI string
	httpServer        *http.Server
	idToken           string
	accessToken       string
	refreshToken      string
}

// RefreshToken returns the refresh token.
func (h *Handler) RefreshToken() string {
	return h.refreshToken
}

// AccessToken returns the access token.
func (h *Handler) AccessToken() string {
	return h.accessToken
}

// IDToken returns the id token.
func (h *Handler) IDToken() string {
	return h.idToken
}

// tokenResponse is the expected response
// while sending a request to the
// token endpoint.
type tokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// errorResponse describes the response
// from the token endpoint on error.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorHint        string `json:"error_hint"`
}

// NewHandler creates a new oauth callback server.
// It takes functional parameters to change default options
// such as the server port
// It returns the newly created server or an err if
// something went wrong.
func NewHandler(hydraBaseURL, clientID string, opts ...func(*Handler) error) (*Handler, error) {
	rand.Seed(time.Now().UnixNano())
	// create server with default options
	var handler = Handler{
		shutdownChannel: make(chan error, 1),
		port:            8123,
		hydraBaseUrl:    hydraBaseURL,
		clientID:        clientID,
		scope:           "openid",
		doneMessage:     "DONE (you may close this window now)",
	}
	// run functional options
	for _, op := range opts {
		err := op(&handler)
		if err != nil {
			return nil, fmt.Errorf("setting server option failed: %w", err)
		}
	}
	handler.redirectURI = fmt.Sprintf("http://localhost:%v", handler.port)
	return &handler, nil
}

// RunHydraAuthCodeFlow starts a new authentication flow.
// It starts serving the callback http server and opens
// the oauth url.
func (h *Handler) RunHydraAuthCodeFlow() error {
	go func() {
		// run callback server
		err := h.serve()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("unable to serve: %s", err)
		}
	}()
	h.state = generateRandomString(28)
	h.verifier = generateRandomString(64)
	h.challenge = pkceChallengeFromVerifier(h.verifier)
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("code_challenge_method", "S256")
	params.Set("client_id", h.clientID)
	params.Set("scope", h.scope)
	params.Set("redirect_uri", h.redirectURI)
	params.Set("state", h.state)
	params.Set("code_challenge", h.challenge)
	u := fmt.Sprintf("%s/oauth2/auth?%s", h.hydraBaseUrl, params.Encode())
	cmd := exec.Command("open", u)
	err := cmd.Start()
	if err != nil {
		h.shutdownChannel <- fmt.Errorf("unable to run open command: %w", err)
	}
	// wait for shutdown
	err = <-h.shutdownChannel
	h.shutdown()
	return err
}

// Cancel cancels the login flow.
func (h *Handler) Cancel() {
	h.shutdownChannel <- fmt.Errorf("the login flow was canceled")
}

// Logout logs out.
func (h *Handler) Logout() error {
	if h.idToken == "" {
		return fmt.Errorf("id token not existing, unable to log out")
	}
	h.state = generateRandomString(28)
	params := url.Values{}
	params.Set("state", h.state)
	params.Set("id_token_hint", h.idToken)
	u := fmt.Sprintf("%s/oauth2/sessions/logout?%s", h.hydraBaseUrl, params.Encode())
	cmd := exec.Command("open", u)
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("unable to open logout url: %w", err)
	}
	h.idToken = ""
	h.accessToken = ""
	return nil
}

// generateRandomString generates a random string with the given length
// which can be used for the state or the verifier.
func generateRandomString(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// pkceChallengeFromVerifier creates a sha256 challenge
// from the given verifier.
func pkceChallengeFromVerifier(v string) string {
	h := sha256.New()
	h.Write([]byte(v))
	return base64urlencode(h.Sum(nil))
}

// base64urlencode creates a base64 string and encodes it
// for using it as a url.
func base64urlencode(msg []byte) string {
	e := base64.StdEncoding.EncodeToString(msg)
	e = strings.Replace(e, "+", "-", -1)
	e = strings.Replace(e, "/", "_", -1)
	e = strings.Replace(e, "=", "", -1)
	return e
}

// Serve starts the http server, which serves the callback route
func (h *Handler) serve() error {
	m := http.NewServeMux()
	m.HandleFunc("/", h.callbackHandler)
	h.httpServer = &http.Server{Addr: fmt.Sprintf(":%v", h.port), Handler: m}
	return h.httpServer.ListenAndServe()
}

// callbackHandler is the callback function for the http requests.
func (h *Handler) callbackHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, h.doneMessage)
	q := r.URL.Query()
	e := q.Get("err")
	if e != "" {
		// flow was not successful, callback received an err
		e = fmt.Sprintf("%s - %s", e, q.Get("error_description"))
		u := q.Get("error_uri")
		if u != "" {
			e = fmt.Sprintf("%s - uri %s", e, u)
		}
		h.shutdownChannel <- fmt.Errorf(e)
		return
	}
	if s := q.Get("state"); s != h.state {
		h.shutdownChannel <- fmt.Errorf("states do not match, got %s expected %s", s, h.state)
		return
	}
	// callback successful, start authorization_code flow
	tokenUrl := fmt.Sprintf("%s/oauth2/token", h.hydraBaseUrl)
	code := q.Get("code")
	v := url.Values{}
	v.Set("grant_type", "authorization_code")
	v.Set("client_id", h.clientID)
	v.Set("code_verifier", h.verifier)
	v.Set("code", code)
	v.Set("redirect_uri", h.redirectURI)

	req, err := http.NewRequest("POST", tokenUrl, strings.NewReader(v.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		h.shutdownChannel <- fmt.Errorf("creating request for token url %s failed: %w", tokenUrl, err)
		return
	}
	client := http.Client{
		Timeout: time.Second * 5,
	}
	// query token endpoint
	res, err := client.Do(req)
	if err != nil {
		h.shutdownChannel <- fmt.Errorf("request to token url %s failed: %w", tokenUrl, err)
		return
	}
	defer res.Body.Close()
	// unexpected status
	if res.StatusCode != 200 {
		var body errorResponse
		err = json.NewDecoder(res.Body).Decode(&body)
		if err != nil {
			h.shutdownChannel <- fmt.Errorf("unexpected status code %v in response from %s and unable to decode response body", res.StatusCode, tokenUrl)
			return
		}
		h.shutdownChannel <- fmt.Errorf("unexpected status code %v in response from %s: %s: %s - hint: %s", res.StatusCode, tokenUrl, body.Error, body.ErrorDescription, body.ErrorHint)
		return
	}
	// decode response
	var body tokenResponse
	err = json.NewDecoder(res.Body).Decode(&body)
	if err != nil {
		h.shutdownChannel <- fmt.Errorf("failed to decode response from token endpoint: %w", err)
		return
	}
	// success
	h.idToken = body.IDToken
	h.accessToken = body.AccessToken
	h.refreshToken = body.RefreshToken
	h.shutdownChannel <- nil
}

// shutdown stops the http server gracefully.
func (h *Handler) shutdown() error {
	if h.httpServer == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return h.httpServer.Shutdown(ctx)
}

// SetPort changes the port on which the callback server listens.
// The default port is 8123.
// SetPort returns an err if an invalid port is given.
func SetPort(port int) func(*Handler) error {
	return func(srv *Handler) error {
		if port <= 0 {
			return fmt.Errorf("invalid port number: %v", port)
		}
		srv.port = port
		return nil
	}
}
