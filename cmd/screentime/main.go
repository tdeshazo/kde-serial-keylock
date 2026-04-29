package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tdeshazo/kde-serial-keylock/internal/screentime"
)

func main() {
	var (
		coordinator = flag.String("coordinator", "http://127.0.0.1:8787", "screen-time coordinator base URL")
		timeout     = flag.Duration("timeout", 3*time.Second, "HTTP request timeout")
		jsonOut     = flag.Bool("json", false, "print raw JSON")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  screentime status <user>\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  screentime set <user> <duration>\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  screentime add <user> <duration>\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  screentime clear <user>\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  screentime state\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Durations accept raw seconds or values like 30m, 1h, 1h30m.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	client := screentime.Client{
		BaseURL: *coordinator,
		HTTP:    &http.Client{Timeout: *timeout},
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var (
		result any
		err    error
	)
	switch args[0] {
	case "status":
		if len(args) != 2 {
			exitUsage("status requires <user>")
		}
		result, err = client.Status(ctx, args[1])
	case "set":
		if len(args) != 3 {
			exitUsage("set requires <user> <duration>")
		}
		seconds, parseErr := parseSeconds(args[2])
		if parseErr != nil {
			exitError(parseErr)
		}
		result, err = client.Set(ctx, args[1], seconds)
	case "add":
		if len(args) != 3 {
			exitUsage("add requires <user> <duration>")
		}
		seconds, parseErr := parseSeconds(args[2])
		if parseErr != nil {
			exitError(parseErr)
		}
		result, err = client.Add(ctx, args[1], seconds)
	case "clear":
		if len(args) != 2 {
			exitUsage("clear requires <user>")
		}
		result, err = client.Clear(ctx, args[1])
	case "state":
		if len(args) != 1 {
			exitUsage("state does not accept extra arguments")
		}
		result, err = client.State(ctx)
	default:
		exitUsage("unknown command " + args[0])
	}
	if err != nil {
		exitError(err)
	}
	if *jsonOut {
		printJSON(result)
		return
	}
	printHuman(result)
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
		return 0, fmt.Errorf("parse duration %q: %w", s, err)
	}
	if d < 0 {
		return 0, errors.New("duration cannot be negative")
	}
	return int(d.Seconds()), nil
}

func printHuman(v any) {
	switch x := v.(type) {
	case screentime.UserStatus:
		fmt.Printf("user=%s state=%s remaining=%s should_lock=%v", x.UserID, x.State, formatDuration(x.RemainingSeconds), x.ShouldLock)
		if len(x.ActiveDevices) > 0 {
			fmt.Printf(" active_devices=%s", strings.Join(x.ActiveDevices, ","))
		}
		fmt.Println()
	case screentime.Snapshot:
		fmt.Println("Users:")
		if len(x.Users) == 0 {
			fmt.Println("  none")
		}
		for _, u := range x.Users {
			fmt.Printf("  %s: state=%s remaining=%s\n", u.ID, u.State, formatDuration(u.RemainingSeconds))
		}
		fmt.Println("Devices:")
		if len(x.Devices) == 0 {
			fmt.Println("  none")
		}
		for _, d := range x.Devices {
			fmt.Printf("  %s: user=%s locked=%v last_seen=%s\n", d.ID, d.UserID, d.Locked, d.LastSeen.Format(time.RFC3339))
		}
	default:
		printJSON(v)
	}
}

func formatDuration(seconds int) string {
	if seconds <= 0 {
		return "0s"
	}
	return (time.Duration(seconds) * time.Second).String()
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		exitError(err)
	}
	fmt.Println(string(b))
}

func exitUsage(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	fmt.Fprintln(os.Stderr)
	flag.Usage()
	os.Exit(2)
}

func exitError(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
