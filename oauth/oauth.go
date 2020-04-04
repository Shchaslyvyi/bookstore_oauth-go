package oauth

import (
	"encoding/json"
	"fmt"
	"golang-restclient/rest"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shchaslyvyi/bookstore_oauth-go/oauth/errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-Id"
	headerXCallerID = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	ID       int64 `json:"id"`
	UserID   int64 `json:"user_id"`
	ClientID int64 `json:"client_id"`
}

// IsPublic func shows if the request is public
func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

// GetCallerID returns the caller id
func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

// GetClientID returns the client id
func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

// AuthenticateRequest func authenticates the request
func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenID := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenID == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenID)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))
	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))

	return nil
}

// cleanRequest func cleans the request header
func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

// getAccessToken func returns the access token
func getAccessToken(accessTokenID string) (*accessToken, *errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenID))
	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("Invalid rest-client response whet trying to get access token.")
	}
	if response.StatusCode > 299 {
		var restErr errors.RestErr
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, errors.NewInternalServerError("Invalid error interface when trying to get access token.")
		}
		return nil, &restErr
	}
	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("Error when trying to unmarshall get access token response.")
	}
	return &at, nil
}
