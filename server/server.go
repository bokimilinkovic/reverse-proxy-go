package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

const (
	ErrorTypeBadRequest           = "MALFORMED_JSON"
	ErrorTypeAuthentication       = "AUTHENTICATION"
	ErrorTypeAuthorization        = "AUTHORIZATION"
	ErrorTypeMethodNotAllowed     = "METHOD_NOT_ALLOWED"
	ErrorTypeRequestTimeout       = "REQUEST_TIMEOUT"
	ErrorTypeRequestTooLarge      = "REQUEST_TOO_LARGE"
	ErrorTypeMediaTypeUnsupported = "MEDIA_TYPE_UNSUPPORTED"
	ErrorTypeWebhookError         = "WEBHOOK_ERROR"
	ErrorTypeWebhookUnavailable   = "WEBHOOK_UNAVAILABLE"
	ErrorTypeWebhookTimeout       = "WEBHOOK_TIMEOUT"

	//Custom error codes.
	ErrorCodeBadRequest                 = 400000
	ErrorCodeAuthenticationNoToken      = 401000
	ErrorCodeAuthenticationInvalidToken = 401000
	ErrorCodeAuthorization              = 403000
	ErrorCodeMethodNotAllowed           = 405000
	ErrorCodeRequestTimeout             = 408000
	ErrorCodeRequestTooLarge            = 413000
	ErrorCodeMediaTypeUnsupported       = 415000
	ErrorCodeWebhookError               = 500000
	ErrorCodeWebhookUnavailable         = 503000
	ErrorCodeWebhookTimeout             = 504000

	TimeoutSeconds = 5
)

type Status struct {
	version     string
	buildDate   string
	description string
}

type Server struct {
	*gin.Engine
	proxy  *httputil.ReverseProxy
	status *Status
}

type CustomError struct {
	Message   string `json:"message"`
	Type      string `json:"type"`
	Code      int    `json:"code"`
	RequestID string `json:"request_id"`
}

type ErrorResponse struct {
	Error CustomError `json:"error"`
}

func newErrorResponse(code int, typ, message string) ErrorResponse {
	return ErrorResponse{
		Error: CustomError{
			Message: message,
			Code:    code,
			Type:    typ,
		},
	}
}

//Response body if status code is 200.
type StatusOKResponse struct {
	Status        string   `json:"status"`
	ErrorList     []string `json:"errorList"`
	SandboxUUID   *string  `json:"sandboxUuid"`
	OpportunityID *string  `json:"opportunity_id"`
}

func NewStatus(version, buildDate, description string) *Status {
	return &Status{
		version:     version,
		buildDate:   buildDate,
		description: description,
	}
}

//Create new server with targeting url.
func New(proxyTargetURL string, status *Status) *Server {
	targetURL, err := url.Parse(proxyTargetURL)
	if err != nil {
		return nil
	}
	proxy := createProxy(targetURL)

	server := &Server{
		proxy:  proxy,
		status: status,
	}
	server.setupRoutes()
	return server
}

func (s *Server) setupRoutes() {
	router := gin.Default()
	router.GET("/version", func(c *gin.Context) {
		response := fmt.Sprintf(`version="%s" buildDate="%s" description="%s"`,
			s.status.version,
			s.status.buildDate,
			s.status.description,
		)
		c.String(http.StatusOK, "%s", response)
	})
	router.NoRoute(func(c *gin.Context) {
		s.proxy.ServeHTTP(c.Writer, c.Request)
	})

	s.Engine = router
}

func createProxy(proxyTargetURL *url.URL) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{}

	proxy.Director = func(req *http.Request) {
		targetQuery := proxyTargetURL.RawQuery
		req.URL.Scheme = proxyTargetURL.Scheme
		req.URL.Host = proxyTargetURL.Host
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Accept-Encoding", "*")
		req.URL.Path = singleJoiningSlash(proxyTargetURL.Path, req.URL.Path)
		req.Host = proxyTargetURL.Host

		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}

	proxy.Transport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: TimeoutSeconds * time.Second,
		}).Dial,
	}

	proxy.ModifyResponse = modifyResponse

	return proxy
}

//Modifies response body depending on status code.
func modifyResponse(resp *http.Response) error {
	var modifiedResponse ErrorResponse
	requestID := resp.Request.Header.Get("X-Request-ID")
	log.SetOutput(os.Stdout)

	switch resp.StatusCode {
	case http.StatusOK:
		var responseOK StatusOKResponse
		if err := json.NewDecoder(resp.Body).Decode(&responseOK); err != nil {
			log.Errorf("Error decoding response: %v", err)
			return err
		}
		log.WithFields(log.Fields{
			"content":     responseOK,
			"status_code": resp.StatusCode,
		}).Info("Tripica's original response")

		if responseOK.Status != "KO" {
			return passthroughBody(responseOK, resp)
		}
		errors := strings.Join(responseOK.ErrorList, " ")
		modifiedResponse = newErrorResponse(
			ErrorCodeBadRequest,
			ErrorTypeBadRequest,
			"Invalid json sent. Tripica returns error: "+errors)
		resp.StatusCode = http.StatusBadRequest
	case http.StatusBadRequest:
		modifiedResponse = newErrorResponse(
			ErrorCodeBadRequest,
			ErrorTypeBadRequest,
			"Improper json format. Check your payload or contact tripica for more information")
	case http.StatusUnauthorized:
		if resp.Request.Header.Get("Authorization") == "" {
			modifiedResponse = newErrorResponse(
				ErrorCodeAuthenticationNoToken,
				ErrorTypeAuthentication,
				"Missing authentication token")
		} else {
			modifiedResponse = newErrorResponse(
				ErrorCodeAuthenticationInvalidToken,
				ErrorTypeAuthentication,
				"Authentication token is invalid")
		}
	case http.StatusForbidden:
		modifiedResponse = newErrorResponse(
			ErrorCodeAuthorization,
			ErrorTypeAuthorization,
			"Missing privileges to invoke the webhook")
	case http.StatusMethodNotAllowed:
		modifiedResponse = newErrorResponse(
			ErrorCodeMethodNotAllowed,
			ErrorTypeMethodNotAllowed,
			"HTTP method not allowed. Example: webhook providing a POST endpoint, but a GET request was sent")
	case http.StatusRequestTimeout:
		modifiedResponse = newErrorResponse(
			ErrorCodeRequestTimeout,
			ErrorTypeRequestTimeout,
			"Request timeout. The webhook did not receive a complete request message within the time that it was prepared to wait, e.g. 30 seconds.")
	case http.StatusRequestEntityTooLarge:
		modifiedResponse = newErrorResponse(
			ErrorCodeRequestTooLarge,
			ErrorTypeRequestTooLarge,
			"JSON payload size too large, e.g. > 1mb")
	case http.StatusUnsupportedMediaType:
		modifiedResponse = newErrorResponse(
			ErrorCodeMediaTypeUnsupported,
			ErrorTypeMediaTypeUnsupported,
			"Wrong body format. Example: webhook only supports request content type as application/json, but requester sent application/x-www-form-urlencoded")
	case http.StatusInternalServerError:
		modifiedResponse = newErrorResponse(
			ErrorCodeWebhookError,
			ErrorTypeWebhookError,
			"Internal error at webhook")
	case http.StatusServiceUnavailable:
		modifiedResponse = newErrorResponse(
			ErrorCodeWebhookUnavailable,
			ErrorTypeWebhookUnavailable,
			"Webhook unavailable")
	case http.StatusGatewayTimeout:
		modifiedResponse = newErrorResponse(
			ErrorCodeWebhookTimeout,
			ErrorTypeWebhookTimeout,
			"Webhook timeout")
	default:
		return nil
	}
	modifiedResponse.Error.RequestID = requestID
	log.WithFields(log.Fields{
		"content":     modifiedResponse,
		"status_code": resp.StatusCode,
	}).Info("Modified response to epilot:")

	return modifyBody(&modifiedResponse, resp)
}

func modifyBody(modifiedResponse *ErrorResponse, resp *http.Response) error {
	responseBytes, err := json.Marshal(&modifiedResponse)
	if err != nil {
		log.Errorf("Error marshaling response: %v", err)
		return err
	}
	body := ioutil.NopCloser(bytes.NewBufferString(string(responseBytes)))
	resp.Body = body
	resp.ContentLength = int64(len(responseBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(responseBytes)))
	resp.Header.Set("Content-Encoding", "*")
	return nil
}

//Once body is decoded and status is OK, no modification is required, so we set response body as it was.
func passthroughBody(responseOK StatusOKResponse, resp *http.Response) error {
	responseBytes, err := json.Marshal(&responseOK)
	if err != nil {
		log.Errorf("Error marshaling response: %v", err)
		return err
	}
	body := ioutil.NopCloser(bytes.NewBufferString(string(responseBytes)))
	resp.Body = body
	resp.ContentLength = int64(len(responseBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(responseBytes)))
	resp.Header.Set("Content-Encoding", "*")
	return nil
}

//Concatenates 2 strings removing 1 sufficient '/' or adding it if there is none
//Example:
//   a := "localhost:8080"							a := "localhost:8080/"
//   b := "api/login/user"							b := "/api/login/user"
//   result = "localhost:8080/api/login/user"		result = "localhost:8080/api/login/user"
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
