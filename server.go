package xhttp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ListenAndServe listens on the TCP network address Addr and handles
// requests on incoming connections.
func ListenAndServe(addr string, handler http.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	slog.Info(fmt.Sprintf("👋 listening on %v", addr))

	server := &http.Server{
		Addr:                         addr,
		Handler:                      handler,
		DisableGeneralOptionsHandler: true,
		ReadTimeout:                  5 * time.Second,
		WriteTimeout:                 5 * time.Second,
		IdleTimeout:                  120 * time.Second,
		MaxHeaderBytes:               http.DefaultMaxHeaderBytes,
	}

	doneCh := make(chan os.Signal, 1)

	go func() {
		if err := server.Serve(ln); err != nil {
			if err != http.ErrServerClosed {
				slog.Error("error serving client", "err", err)
				close(doneCh)
			}
		}
	}()

	signal.Notify(doneCh, syscall.SIGINT, syscall.SIGTERM)
	<-doneCh

	slog.Info("☠️  shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return server.Shutdown(ctx)
}
