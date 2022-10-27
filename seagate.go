package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

type LyveAuthToken string

const AuthEndpoint = "https://auth.lyve.seagate.com"
const ApiEndpoint = "https://api.lyvecloud.seagate.com"

type AuthRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
	GrantType    string `json:"grant_type"`
}

type AuthResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type ServiceAccountReq struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type ServiceAccountRes struct {
	ID           string `json:"id"`
	AccessKey    string `json:"access_key"`
	AccessSecret string `json:"access_secret"`
}

type PermissionReq struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Actions     string   `json:"actions"`
	Buckets     []string `json:"buckets"`
}

type PermissionRes struct {
	ID string `json:"id"`
}

// CreateServiceAccount function creates a seagate permission and service account, and returns
func CreateServiceAccount(ctx context.Context, seagateKey, seagateSecret, prefix string) (key, secret string, err error) {
	// get an auth token
	authToken, err := LyveGetAuthenticationToken(ctx, seagateKey, seagateSecret)
	if err != nil {
		return "", "", errors.Wrapf(err, "failed to get authentication token")
	}

	// create permission now
	permissionResponse, err := LyveCreatePermission(ctx, authToken, prefix, prefix)
	if err != nil {
		return "", "", errors.Wrapf(err, "failed to create permission")
	}

	serviceReq := ServiceAccountReq{
		Name:        prefix,
		Description: "Service account for " + prefix,
		Permissions: []string{permissionResponse.ID},
	}

	msg, _ := json.Marshal(serviceReq)

	data, err := lyveRESTRequest(ctx, &authToken, "LyveCreateServiceAccount", "PUT", ApiEndpoint+"/v1/service-account", msg)
	if err != nil {
		return "", "", errors.Wrapf(err, "failed to create service account")
	}

	var account ServiceAccountRes
	err = json.Unmarshal(data, &account)
	if err != nil {
		return "", "", errors.WithMessagef(err, "LyveCreateServiceAccount")
	}

	key = account.AccessKey
	secret = account.AccessSecret
	return
}

// LyveCreatePermission function creates a Seagate Lyve permission
func LyveCreatePermission(ctx context.Context, authToken LyveAuthToken, customerName, bucketName string) (*PermissionRes, error) {
	permReq := PermissionReq{
		Name:        bucketName, // must be unique
		Description: customerName,
		Actions:     "all-operations",
		Buckets:     []string{bucketName + "*"}, // the bucket name must be specified as regexp
	}

	msg, _ := json.Marshal(permReq)

	data, err := lyveRESTRequest(ctx, &authToken, "LyveCreatePermission", "PUT", ApiEndpoint+"/v1/permission", msg)
	if err != nil {
		return nil, err
	}

	var permRes PermissionRes

	err = json.Unmarshal(data, &permRes)
	if err != nil {
		return nil, errors.WithMessagef(err, "LyveCreatePermission")
	}

	return &permRes, nil
}

func lyveRESTRequest(ctx context.Context, authToken *LyveAuthToken, apiName string, method string, endpoint string, msg []byte) ([]byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(msg))
	if err != nil {
		return []byte{}, errors.WithMessagef(err, apiName+": make request")
	}

	if authToken != nil {
		req.Header.Set("authorization", "Bearer "+string(*authToken))
	}
	req.Header.Set("content-type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return []byte{}, errors.WithMessagef(err, apiName+": run request")
	}

	if res.StatusCode != 200 {
		type ErrorMsg struct {
			Error string `json:"error"`
		}

		var errorMsg ErrorMsg
		err = json.NewDecoder(res.Body).Decode(&errorMsg)
		if err != nil {
			return []byte{}, errors.WithMessagef(err, apiName+": decode error")
		}
		return []byte{}, fmt.Errorf(apiName+": %s (%s)", res.Status, errorMsg.Error)
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return []byte{}, errors.WithMessagef(err, apiName+": reading body")
	}

	return body, nil
}

func LyveGetAuthenticationToken(ctx context.Context, key, secret string) (LyveAuthToken, error) {
	auth := NewSimpleAuth(key, secret)

	msg, _ := json.Marshal(auth)

	data, err := lyveRESTRequest(ctx, nil, "LyveAuthToken", "POST", AuthEndpoint+"/oauth/token", msg)
	if err != nil {
		return "", err
	}

	var token AuthResponse
	err = json.Unmarshal(data, &token)
	if err != nil {
		return "", errors.WithMessagef(err, "LyveAuthenticationsToken")
	}

	return (LyveAuthToken)(token.AccessToken), nil
}

func NewSimpleAuth(clientId, clientSecret string) *AuthRequest {
	return &AuthRequest{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Audience:     "https://lyvecloud/customer/api",
		GrantType:    "client_credentials",
	}
}
