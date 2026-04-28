package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tdeshazo/kde-serial-keylock/internal/config"
	"github.com/tdeshazo/kde-serial-keylock/internal/token"
)

func main() {
	var (
		configPath = flag.String("config", "config.json", "path to JSON config")
		debug      = flag.Bool("debug", false, "log serial timer diagnostics")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  settimer [flags] status\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  settimer [flags] read\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  settimer [flags] set <duration|seconds>\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  settimer [flags] add <duration|seconds>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	command := "status"
	if len(args) > 0 {
		command = strings.ToLower(args[0])
	}
	if command == "read" {
		command = "status"
	}
	if command != "status" && command != "set" && command != "add" {
		failUsage("unknown command %q", command)
	}
	if command == "status" && len(args) > 1 {
		failUsage("status does not take an argument")
	}
	if (command == "set" || command == "add") && len(args) != 2 {
		failUsage("%s requires one duration or seconds argument", command)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fail("load config: %v", err)
	}

	var secret []byte
	if command == "set" || command == "add" {
		value := os.Getenv(cfg.Auth.SecretEnv)
		if value == "" {
			fail("%s is empty; set it to the shared token secret", cfg.Auth.SecretEnv)
		}
		secret = []byte(value)
	}

	auth := token.Authenticator{
		Cfg: token.Config{
			Port:    cfg.Serial.Port,
			Baud:    cfg.Serial.Baud,
			VID:     cfg.Serial.VID,
			PID:     cfg.Serial.PID,
			Timeout: cfg.ChallengeTimeout(),
			Debug:   *debug,
		},
		Secret: secret,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var status token.TimerStatus
	switch command {
	case "status":
		status, err = auth.TimerStatus(ctx)
	case "set":
		var seconds int
		seconds, err = parseSeconds(args[1])
		if err == nil {
			status, err = auth.SetTimer(ctx, seconds)
		}
	case "add":
		var seconds int
		seconds, err = parseSeconds(args[1])
		if err == nil {
			status, err = auth.AddTimer(ctx, seconds)
		}
	}
	if err != nil {
		if isNoKeyError(err) {
			fail("no key present: %v", err)
		}
		fail("%s timer: %v", command, err)
	}

	fmt.Printf("port=%s state=%s remaining=%s remaining_seconds=%d\n",
		status.Port,
		status.State,
		formatSeconds(status.Remaining),
		status.Remaining,
	)
	if status.Persist == "failed" {
		fmt.Fprintln(os.Stderr, "warning: timer state changed in RAM, but the key could not persist it to flash")
	}
}

func parseSeconds(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 {
			return 0, errors.New("duration cannot be negative")
		}
		return n, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("parse duration %q: use seconds or Go duration syntax like 30m or 1h15m", s)
	}
	if d < 0 {
		return 0, errors.New("duration cannot be negative")
	}
	return int(d.Round(time.Second) / time.Second), nil
}

func formatSeconds(seconds int) string {
	if seconds <= 0 {
		return "0s"
	}
	return (time.Duration(seconds) * time.Second).String()
}

func isNoKeyError(err error) bool {
	text := err.Error()
	return strings.Contains(text, "no matching serial ports") ||
		strings.Contains(text, "no serial ports attempted")
}

func failUsage(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n\n", args...)
	flag.Usage()
	os.Exit(2)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
