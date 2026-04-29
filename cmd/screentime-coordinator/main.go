package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tdeshazo/kde-serial-keylock/internal/screentime"
)

func main() {
	var (
		addr         = flag.String("addr", "127.0.0.1:8787", "HTTP listen address")
		statePath    = flag.String("state", "screen-time-state.json", "path to JSON state file")
		onlineWindow = flag.Duration("online-window", 10*time.Second, "how recently a device must report unlocked state to count as active")
		debug        = flag.Bool("debug", false, "enable debug logging")
	)
	flag.Parse()
	configureLogging(*debug)

	store, err := screentime.Load(*statePath)
	if err != nil {
		slog.Error("load screen-time state failed", "path", *statePath, "err", err)
		os.Exit(1)
	}

	handler := screentime.Server{Store: store, OnlineWindow: *onlineWindow}.Handler()
	srv := &http.Server{Addr: *addr, Handler: handler}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("screen-time coordinator started", "addr", *addr, "state", *statePath, "online_window", *onlineWindow)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("screen-time coordinator failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("screen-time coordinator shutdown failed", "err", err)
		os.Exit(1)
	}
	slog.Info("screen-time coordinator stopped")
}

func configureLogging(debug bool) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}
