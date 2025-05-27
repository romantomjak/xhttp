package xhttp

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

const (
	SigningMethodHS256 = "HS256"
	SigningMethodHS384 = "HS384"
	SigningMethodHS512 = "HS512"
)

var HMACSigningMethods = []string{
	SigningMethodHS256,
	SigningMethodHS384,
	SigningMethodHS512,
}

// JWTSubject parses JWT token from the Authorization header.
//
// The claim subject is parsed as a UUID and added to the request context.
// If the token is missing or invalid, the request handling is stopped and
// a JSON error is returned to the client.
//
// Note: human-memorizable passwords must not be directly used as the secret.
func JWTSubject(h http.Handler, issuer string, audience string, secret []byte, validMethods []string) http.Handler {
	parser := &jwt.Parser{
		ValidMethods: validMethods,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if header == "" {
			SlogFromContext(r.Context()).Error("missing authorization header")
			writeJSONError(w, r, http.StatusUnauthorized, "Authorization token required")
			return
		}

		parts := strings.Fields(header)
		if len(parts) != 2 {
			SlogFromContext(r.Context()).Error("invalid authorization header format")
			writeJSONError(w, r, http.StatusUnauthorized, "Authorization header must be in the format: Bearer <token>")
			return
		}
		if strings.ToLower(parts[0]) != "bearer" {
			SlogFromContext(r.Context()).Error("invalid authorization type", "type", parts[0])
			writeJSONError(w, r, http.StatusUnauthorized, "Authorization type must be Bearer")
			return
		}

		// Signing method and signature verification is handled by the parser.
		token, err := parser.ParseWithClaims(parts[1], new(jwt.StandardClaims), func(token *jwt.Token) (any, error) {
			return secret, nil
		})
		if err != nil {
			SlogFromContext(r.Context()).Error("parse authorization token", "err", err)
			writeJSONError(w, r, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		claims, ok := token.Claims.(*jwt.StandardClaims)
		if !ok {
			SlogFromContext(r.Context()).Error(fmt.Sprintf("cannot assert %T as jwt.StandardClaims", token.Claims))
			writeJSONError(w, r, http.StatusUnauthorized, "Invalid token claims")
			return
		}

		// Time based claims such as exp, iat, nbf have already been validated
		// during parsing, but unfortunately, they are treated as optional, so
		// we manually validate these as required.
		switch now := time.Now().Unix(); {
		case !claims.VerifyExpiresAt(now, true):
			SlogFromContext(r.Context()).Error("token is expired", "exp", time.Unix(claims.ExpiresAt, 0).Format(time.RFC3339))
			writeJSONError(w, r, http.StatusUnauthorized, "Invalid or expired token")
			return
		case !claims.VerifyIssuedAt(now, true):
			SlogFromContext(r.Context()).Error("token used before issued", "iat", time.Unix(claims.IssuedAt, 0).Format(time.RFC3339))
			writeJSONError(w, r, http.StatusUnauthorized, "Invalid or expired token")
			return
		case !claims.VerifyNotBefore(now, true):
			SlogFromContext(r.Context()).Error("token is not valid yet", "nbf", time.Unix(claims.NotBefore, 0).Format(time.RFC3339))
			writeJSONError(w, r, http.StatusUnauthorized, "Invalid or expired token")
			return
		case !claims.VerifyIssuer(issuer, true):
			SlogFromContext(r.Context()).Error("token has not been issued by us", "iss", claims.Issuer)
			writeJSONError(w, r, http.StatusUnauthorized, "Invalid or expired token")
			return
		case !claims.VerifyAudience(audience, true):
			SlogFromContext(r.Context()).Error("token is not intended for us", "aud", claims.Audience)
			writeJSONError(w, r, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		subject, err := uuid.Parse(claims.Subject)
		if err != nil {
			SlogFromContext(r.Context()).Error("parse token subject as uuid", "subject", claims.Subject, "err", err)
			writeJSONError(w, r, http.StatusUnauthorized, "Invalid token subject")
			return
		}

		ctx := newContextWithJWTClaimSubject(r.Context(), subject)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

const (
	// The requesting code from any origin is allowed to access the resource.
	// For requests without credentials, the literal value * can be specified
	// as a wildcard. Attempting to use the wildcard with credentials results
	// in an error.
	OriginWildcard = "*"

	// The value null should not be used. It may seem safe to return
	// Access-Control-Allow-Origin: "null"; however, the origin of resources that
	// use a non-hierarchical scheme (such as data: or file:) and sandboxed
	// documents is serialized as null. Many browsers will grant such documents
	// access to a response with an Access-Control-Allow-Origin: null header, and
	// any origin can create a hostile document with a null origin. Therefore,
	// the null value for the Access-Control-Allow-Origin header should be avoided.
	OriginNull = "null"
)

// CORS sets Cross Origin Resource Sharing headers on the response.
//
// It allows requests from the specified origin and exposes specific headers (e.g.,
// the Location header) to scripts running in the browser.
func CORS(h http.Handler, origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := w.Header()

		headers.Set("Access-Control-Allow-Origin", origin)

		// If the origin is not wildcard, the response should also include
		// a Vary response header with the value Origin — to indicate to
		// browsers that server responses can differ based on the value of
		// the Origin request header.
		if origin != "" && origin != OriginWildcard && origin != OriginNull {
			headers.Add("Vary", "Origin")
		}

		// Indicates the HTTP headers that can be used during the actual request.
		// This header is required if the preflight request contains Access-Control-
		// Request-Headers (which it will if called from JavaScript).
		headers.Set("Access-Control-Allow-Headers", "authorization")

		// Indicates which response headers should be made available to scripts
		// running in the browser. Used by javascript libraries such as axios
		// to properly redirect a HTTP 201 response containing a Location header.
		headers.Set("Access-Control-Expose-Headers", "Location")

		h.ServeHTTP(w, r)
	})
}

const (
	TrustedHeaderCfConnectingIP = "Cf-Connecting-Ip"
	TrustedHeaderXForwardedFor  = "X-Forwarded-For"
	TrustedHeaderXRealIP        = "X-Real-Ip"
)

// ClientIP extracts the remote client's IP address from a list of trusted
// headers (e.g., X-Forwarded-For). If no valid IP is found, it falls back
// to the remote address of the request.
//
// Note: do *not* trust X-Real-Ip and X-Forwarded-For headers unless the server
// is behind a trusted reverse proxy. Clients can set those headers to arbitrary
// values.
func ClientIP(h http.Handler, trustedHeaders ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ipAddr string

		// Walk trusted headers to find the first, non-empty client IP.
		for _, header := range trustedHeaders {
			for ip := range strings.SplitSeq(r.Header.Get(header), ",") {
				ip := strings.TrimSpace(ip)
				if ip != "" {
					ipAddr = ip
					break
				}
			}
		}

		if ipAddr == "" {
			// The HTTP server sets the RemoteAddr to a valid value, so it's safe
			// to ignore the error here.
			ipAddr, _, _ = net.SplitHostPort(r.RemoteAddr)
		}

		ctx := newContextWithClientIP(r.Context(), ipAddr)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Slog attaches a structured logger to the request context.
//
// It includes request metadata such as a unique request ID, method, path, and
// the remote address.
func Slog(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.NewRandom()
		if err != nil {
			slog.Error("new request id", "err", err)
			writeJSONError(w, r, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}

		ctx := newContextWithSlog(r.Context(), slog.With(
			"request_id", id.String(),
			"method", r.Method,
			"remote_addr", r.RemoteAddr,
			"path", r.URL.Path,
		))
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

var gzPool = sync.Pool{
	New: func() interface{} {
		w := gzip.NewWriter(io.Discard)
		return w
	},
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// Gzip compresses the response using gzip if the client supports it.
func Gzip(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Accept-Encoding")

		if !strings.Contains(header, "gzip") {
			h.ServeHTTP(w, r)
			return
		}

		// Strip gzip from the accept-encoding header to prevent double-gzipping.
		header = strings.ReplaceAll(header, "gzip", "")
		r.Header.Set("Accept-Encoding", header)

		w.Header().Set("Content-Encoding", "gzip")

		// Get a gzip.Writer from the pool to reduce allocations.
		gz := gzPool.Get().(*gzip.Writer)
		defer gzPool.Put(gz)

		gz.Reset(w)
		defer gz.Close()

		gzw := &gzipResponseWriter{Writer: gz, ResponseWriter: w}
		h.ServeHTTP(gzw, r)
	})
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	bytesSent  int64
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(buf []byte) (int, error) {
	n, err := r.ResponseWriter.Write(buf)
	r.bytesSent += int64(n)
	return n, err
}

// AccessLog logs detailed information about each request, including the HTTP method,
// path, status code, number of bytes sent, etc.
//
// Note: this middleware should be applied as the outermost (i.e., last in the chain).
// Despite being applied last, it will be executed first.
func AccessLog(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap the ResponseWriter to capture status code and bytes sent.
		rr := &responseRecorder{w, http.StatusOK, 0}

		h.ServeHTTP(rr, r)

		SlogFromContext(r.Context()).Info(
			fmt.Sprintf("%s %s %d", r.Method, r.URL.Path, rr.statusCode),
			"remote_addr", r.RemoteAddr,
			"host", r.Host,
			"method", r.Method,
			"path", r.URL.Path,
			"proto", r.Proto,
			"status_code", rr.statusCode,
			"bytes_sent", rr.bytesSent,
			"referer", r.Header.Get("Referer"),
			"user_agent", r.UserAgent(),
		)
	})
}

// writeJSONError is a helper to send a JSON error response to client.
func writeJSONError(w http.ResponseWriter, r *http.Request, status int, message string) {
	h := w.Header()

	// Delete the Content-Length header, which might be for some other content.
	h.Del("Content-Length")

	// There might be content type already set, but we reset it to
	// application/json for the error message.
	h.Set("Content-Type", "application/json")

	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		SlogFromContext(r.Context()).Error("write json error response", "err", err)
	}
}
