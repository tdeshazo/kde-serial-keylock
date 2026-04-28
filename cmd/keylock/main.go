package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tdeshazo/kde-serial-keylock/internal/config"
	"github.com/tdeshazo/kde-serial-keylock/internal/locker"
	"github.com/tdeshazo/kde-serial-keylock/internal/token"
)

func main() {
	var (
		configPath = flag.String("config", "config.json", "path to JSON config")
		listPorts  = flag.Bool("list-ports", false, "list detected serial ports and exit")
		once       = flag.Bool("once", false, "check once: unlock if token authenticates, otherwise lock")
		authDebug  = flag.Bool("auth-debug", false, "log serial challenge/response diagnostics")
		tokenDiag  = flag.Bool("token-diag", false, "ask token to report key hash and HMAC test vector")
	)
	flag.Parse()

	if *listPorts {
		ports, err := token.ListPorts()
		if err != nil {
			log.Fatalf("list ports: %v", err)
		}
		if len(ports) == 0 {
			fmt.Println("no /dev/ttyACM*, /dev/ttyUSB*, or /dev/serial/by-id/* ports found")
			return
		}
		for _, p := range ports {
			if p.Symlink != "" {
				fmt.Printf("%s -> %s", p.Symlink, p.Name)
			} else {
				fmt.Print(p.Name)
			}
			if p.VID != "" || p.PID != "" {
				fmt.Printf(" vid=%s pid=%s", p.VID, p.PID)
			}
			fmt.Println()
		}
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	secret := os.Getenv(cfg.Auth.SecretEnv)
	if secret == "" {
		log.Fatalf("%s is empty; set it to the shared token secret", cfg.Auth.SecretEnv)
	}
	logDaemonHash()

	l, err := locker.New(cfg.Locker.Backend, cfg.Locker.DryRun)
	if err != nil {
		log.Fatalf("locker: %v", err)
	}
	auth := token.Authenticator{
		Cfg: token.Config{
			Port:    cfg.Serial.Port,
			Baud:    cfg.Serial.Baud,
			VID:     cfg.Serial.VID,
			PID:     cfg.Serial.PID,
			Timeout: cfg.ChallengeTimeout(),
			Debug:   *authDebug,
		},
		Secret: []byte(secret),
	}
	if *authDebug {
		log.Printf("auth debug enabled: challenge nonces and expected per-challenge HMACs will be logged")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *tokenDiag {
		checkTokenDiagnostic(ctx, auth)
		return
	}

	if *once {
		checkOnce(ctx, auth, l, cfg.Locker.UnlockWhenAuthenticated)
		return
	}

	runDaemon(ctx, auth, l, cfg)
}

func logDaemonHash() {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("daemon hash unavailable: executable path: %v", err)
		return
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		log.Printf("daemon hash unavailable: read %s: %v", exe, err)
		return
	}
	daemonHash := sha256.Sum256(b)
	log.Printf("daemon hash: path=%s sha256=%s", exe, hex.EncodeToString(daemonHash[:]))
}

func checkTokenDiagnostic(ctx context.Context, auth token.Authenticator) {
	diag, err := auth.Diagnose(ctx)
	if err != nil {
		log.Printf("token diagnostic failed: %v", err)
		for _, line := range diag.RawLines {
			log.Printf("token diagnostic raw line: %q", line)
		}
		os.Exit(2)
	}
	log.Printf("token diagnostic on %s", diag.Port)
	log.Printf("host key hash: sha256=%s", diag.ExpectedKeyHash)
	log.Printf("token key hash: sha256=%s match=%v", diag.KeyHash, diag.KeyHashMatches())
	log.Printf("host test hmac: message=%q hmac=%s", "KEYLOCK-TEST-NONCE", diag.ExpectedTestMAC)
	log.Printf("token test hmac: hmac=%s match=%v", diag.TestMAC, diag.TestMACMatches())
	if !diag.KeyHashMatches() || !diag.TestMACMatches() {
		os.Exit(2)
	}
}

func checkOnce(ctx context.Context, auth token.Authenticator, l locker.Locker, unlock bool) {
	port, err := auth.Authenticate(ctx)
	if err == nil {
		log.Printf("token authenticated on %s", port)
		if unlock {
			if err := l.Unlock(ctx); err != nil {
				log.Printf("unlock request failed: %v", err)
			}
		}
		return
	}
	log.Printf("token absent or invalid: %v", err)
	if err := l.Lock(ctx); err != nil {
		log.Printf("lock request failed: %v", err)
	}
	os.Exit(2)
}

func runDaemon(ctx context.Context, auth token.Authenticator, l locker.Locker, cfg config.Config) {
	log.Printf("keylock started: backend=%s dry_run=%v", cfg.Locker.Backend, cfg.Locker.DryRun)
	log.Printf("remove or fail the token to lock; authenticate the token to request unlock")
	defer pauseTimerOnStop(auth)

	authenticated := false
	lastLock := time.Time{}
	var timerLockState *bool
	lockStateErrLogged := false
	var timerEventErrState *bool
	poll := cfg.PollInterval()
	if poll <= 0 {
		poll = time.Second
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("stopping: %v", ctx.Err())
			return
		case <-ticker.C:
		}

		if active, err := l.Active(ctx); err != nil {
			if !lockStateErrLogged {
				log.Printf("lock state query failed: %v", err)
				lockStateErrLogged = true
			}
		} else if timerLockState == nil || *timerLockState != active {
			lockStateErrLogged = false
			status, err := auth.SendTimerLockState(ctx, active)
			if err != nil {
				if timerEventErrState == nil || *timerEventErrState != active {
					log.Printf("timer %s event failed: %v", lockStateName(active), err)
					timerEventErrState = boolPtr(active)
				}
			} else {
				timerLockState = boolPtr(active)
				timerEventErrState = nil
				log.Printf("timer %s event sent to %s: state=%s remaining=%d", lockStateName(active), status.Port, status.State, status.Remaining)
			}
		}

		port, err := auth.Authenticate(ctx)
		if err == nil {
			if !authenticated {
				log.Printf("token authenticated on %s", port)
				if cfg.Locker.UnlockWhenAuthenticated {
					if err := l.Unlock(ctx); err != nil {
						log.Printf("unlock request failed: %v", err)
					}
				}
			}
			authenticated = true
			continue
		}

		if authenticated {
			log.Printf("token lost or failed authentication: %v", err)
		}
		authenticated = false

		if time.Since(lastLock) >= cfg.RelockInterval() {
			if err := l.Lock(ctx); err != nil {
				log.Printf("lock request failed: %v", err)
			} else {
				lastLock = time.Now()
			}
		}
	}
}

func pauseTimerOnStop(auth token.Authenticator) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, err := auth.PauseTimer(ctx)
	if err != nil {
		log.Printf("timer PAUSE event failed during shutdown: %v", err)
		return
	}
	log.Printf("timer PAUSE event sent to %s during shutdown: state=%s remaining=%d", status.Port, status.State, status.Remaining)
}

func boolPtr(v bool) *bool {
	return &v
}

func lockStateName(locked bool) string {
	if locked {
		return "LOCKED"
	}
	return "UNLOCKED"
}
