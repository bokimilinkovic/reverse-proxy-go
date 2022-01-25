package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	proxyserver "github.com/enercity/ed4-svc-epilot-tripica-proxy/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var backend *httptest.Server

func TestMain(m *testing.M) {
	//Mocked backend server
	backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TransferEncoding) > 0 {
			return
		}
		if r.Header.Get("X-Forwarded-For") == "" {
			return
		}
		if c := r.Header.Get("Connection"); c != "" {
			return
		}
		if r.Method == "POST" && r.URL.Path == "/api/user/login/jwt" {
			var values map[string]string
			if err := json.NewDecoder(r.Body).Decode(&values); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if values["email"] == "some-email" && values["password"] == "some-pass" {
				w.WriteHeader(http.StatusCreated)
				_, err := w.Write([]byte("encoded-jwt-token"))
				if err != nil {
					return
				}
				return
			}

			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte("bad credentials"))
			if err != nil {
				return
			}
			return
		}
		if r.URL.Path == "/api/user/1" {
			if r.Method != "GET" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Authorization") != "Bearer 123" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Authorization") == "Bearer 123" && r.Header.Get("Permissions") != "*" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			_, err := w.Write([]byte(`{"username":"user1","password":"123"}`))
			if err != nil {
				return
			}
		}
		if r.URL.Path == "/api/private/billing/account" && r.Method == "POST" {
			var values map[string]string
			if err := json.NewDecoder(r.Body).Decode(&values); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if values["account"] != "testAcc" {
				response := proxyserver.StatusOKResponse{
					Status: "KO",
					ErrorList: []string{
						"BAD_ACCOUNT_PROVIDED",
					},
					OpportunityID: nil,
					SandboxUUID:   nil,
				}
				w.WriteHeader(http.StatusOK)
				responseBytes, err := json.Marshal(&response)
				if err != nil {
					return
				}
				_, err = w.Write(responseBytes)
				if err != nil {
					return
				}
				return
			}
			opId := "asd12"
			boxId := "dsa12"
			response := proxyserver.StatusOKResponse{
				Status:        "OK",
				ErrorList:     nil,
				OpportunityID: &opId,
				SandboxUUID:   &boxId,
			}
			w.WriteHeader(http.StatusOK)
			responseBytes, err := json.Marshal(&response)
			if err != nil {
				return
			}
			_, err = w.Write(responseBytes)
			if err != nil {
				return
			}
		}
	}))
	defer backend.Close()

	serverStatus := proxyserver.NewStatus("test", time.Now().String(), "testing")
	server := proxyserver.New(backend.URL, serverStatus)

	go func() {
		err := server.Run(fmt.Sprintf(":%d", 8080))
		if err != nil {
			return
		}
	}()

	os.Exit(m.Run())
}

func TestProxyBehavior(t *testing.T) {
	assert := assert.New(t)
	client := &http.Client{}

	tests := []struct {
		Name           string
		Request        *http.Request
		ExpectedStatus int
		ExpectedBody   string
	}{
		{
			Name: "Backend's login endpoint returns status created and 'token'",
			Request: createRequest(
				"POST",
				"http://localhost:8080/api/user/login/jwt",
				`{"email":"some-email","password":"some-pass"}`,
				t,
			),
			ExpectedBody:   "encoded-jwt-token",
			ExpectedStatus: http.StatusCreated,
		},
		{
			Name: "Invalid login credentials",
			Request: createRequest(
				"POST",
				"http://localhost:8080/api/user/login/jwt",
				`{"email":"bad-email","password":"wrong-pass"}`,
				t,
			),
			ExpectedBody:   `{"error":{"message":"Improper json format. Check your payload or contact tripica for more information","type":"MALFORMED_JSON","code":400000,"request_id":""}}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Name: "Method not allowed",
			Request: createRequest(
				"POST",
				"http://localhost:8080/api/user/1",
				"",
				t,
			),
			ExpectedBody:   `{"error":{"message":"HTTP method not allowed. Example: webhook providing a POST endpoint, but a GET request was sent","type":"METHOD_NOT_ALLOWED","code":405000,"request_id":""}}`,
			ExpectedStatus: http.StatusMethodNotAllowed,
		},
		{
			Name: "Forbidden GET method for retrieving user",
			Request: createRequest(
				"GET",
				"http://localhost:8080/api/user/1",
				"",
				t,
				map[string]string{"Authorization": "Bearer 123"},
			),
			ExpectedBody:   `{"error":{"message":"Missing privileges to invoke the webhook","type":"AUTHORIZATION","code":403000,"request_id":""}}`,
			ExpectedStatus: http.StatusForbidden,
		},
		{
			Name: "Successfully  returned user",
			Request: createRequest(
				"GET",
				"http://localhost:8080/api/user/1",
				"",
				t,
				map[string]string{
					"Authorization": "Bearer 123",
					"Permissions":   "*",
				},
			),
			ExpectedBody:   `{"username":"user1","password":"123"}`,
			ExpectedStatus: http.StatusAccepted,
		},
		{
			Name: "Bad request on login endpoint",
			Request: createRequest(
				"POST",
				"http://localhost:8080/api/user/login/jwt",
				`{email:"some-email","password":"some-pass"}`,
				t,
				map[string]string{"X-Request-ID": "30f14c6c1fc85cba12bfd093aa8f90e"},
			),
			ExpectedBody:   `{"error":{"message":"Improper json format. Check your payload or contact tripica for more information","type":"MALFORMED_JSON","code":400000,"request_id":"30f14c6c1fc85cba12bfd093aa8f90e"}}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Name: "Status Unauthorized, no token provided",
			Request: createRequest(
				"GET",
				"http://localhost:8080/api/user/1",
				"",
				t,
			),
			ExpectedBody:   `{"error":{"message":"Missing authentication token","type":"AUTHENTICATION","code":401000,"request_id":""}}`,
			ExpectedStatus: http.StatusUnauthorized,
		},
		{
			Name: "Status code is 200, but with status KO and error",
			Request: createRequest(
				"POST",
				"http://localhost:8080/api/private/billing/account",
				`{"account":"testAccs"}`,
				t,
			),
			ExpectedBody:   `{"error":{"message":"Invalid json sent. Tripica returns error: BAD_ACCOUNT_PROVIDED","type":"MALFORMED_JSON","code":400000,"request_id":""}}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			Name: "Status code is 200, with status OK and no errors in list",
			Request: createRequest(
				"POST",
				"http://localhost:8080/api/private/billing/account",
				`{"account":"testAcc"}`,
				t,
			),
			ExpectedBody:   `{"status":"OK","errorList":null,"sandboxUuid":"dsa12","opportunity_id":"asd12"}`,
			ExpectedStatus: http.StatusOK,
		},
	}

	for i := 0; i < len(tests); i++ {
		test := tests[i]
		t.Run(test.Name, func(t *testing.T) {
			resp, err := client.Do(test.Request)
			assert.NoError(err)
			assert.Equal(test.ExpectedStatus, resp.StatusCode)
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			assert.NoError(err)

			assert.Equal(test.ExpectedBody, string(body))
		})
	}
}

func createRequest(method, url, bodyData string, t *testing.T, headers ...map[string]string) *http.Request {
	b := bytes.NewBuffer([]byte(bodyData))
	req, err := http.NewRequestWithContext(context.Background(), method, url, b)
	require.NoError(t, err)
	if len(headers) != 0 {
		for i := 0; i < len(headers); i++ {
			for k, v := range headers[i] {
				req.Header.Set(k, v)
			}
		}

	}
	return req
}
