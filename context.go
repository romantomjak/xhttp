package xhttp

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

// contextKey represents an internal key for storing context values.
type contextKey int

const (
	slogContextKey contextKey = iota
	jwtClaimSubjectContextKey
	clientIPContextKey
)

func newContextWithSlog(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, slogContextKey, logger)
}

// SlogFromContext returns the request-scoped structured logger.
//
// If the middleware has not been applied - the default logger is returned.
func SlogFromContext(ctx context.Context) *slog.Logger {
	logger, ok := ctx.Value(slogContextKey).(*slog.Logger)
	if !ok {
		return slog.Default()
	}
	return logger
}

func newContextWithJWTClaimSubject(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, jwtClaimSubjectContextKey, userID)
}

// JWTSubjectFromContext returns the parsed claim subject.
//
// If the middleware has not been applied or if the subject is not
// a valid UUID - the nil UUID is returned.
func JWTSubjectFromContext(ctx context.Context) uuid.UUID {
	userID, ok := ctx.Value(jwtClaimSubjectContextKey).(uuid.UUID)
	if ok {
		return userID
	}
	return uuid.Nil
}

func newContextWithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPContextKey, ip)
}

// ClientIPFromContext returns the extracted client IP address.
//
// If the middleware has not been applied or the extraction failed,
// an empty string is returned.
func ClientIPFromContext(ctx context.Context) string {
	userIP, ok := ctx.Value(clientIPContextKey).(string)
	if ok {
		return userIP
	}
	return ""
}
