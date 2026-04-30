//go:build !linux

package token

import (
	"context"
	"errors"
)

type HIDInfo struct {
	Path string
	VID  string
	PID  string
	Name string
}

func ListHIDDevices() ([]HIDInfo, error) {
	return nil, errors.New("HID transport is currently implemented only on Linux")
}

func (a Authenticator) authenticateHID(ctx context.Context) (string, error) {
	return "", errors.New("HID transport is currently implemented only on Linux")
}

func (a Authenticator) diagnoseHID(ctx context.Context) (Diagnostic, error) {
	return Diagnostic{}, errors.New("HID transport is currently implemented only on Linux")
}

func (a Authenticator) timerStatusHID(ctx context.Context) (TimerStatus, error) {
	return TimerStatus{}, errors.New("HID transport is currently implemented only on Linux")
}

func (a Authenticator) sendTimerCommandHID(ctx context.Context, commandParts ...string) (TimerStatus, error) {
	return TimerStatus{}, errors.New("HID transport is currently implemented only on Linux")
}
