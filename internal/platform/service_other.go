//go:build !windows && !linux

package platform

import (
	"context"
	"errors"
)

const ServiceName = "moley"

var errNoService = errors.New("the Moley service is not supported on this OS yet")

func RunService(func(context.Context) error) (bool, error) { return false, nil }
func InstallService(string, []string) error                { return errNoService }
func UninstallService() error                              { return errNoService }
func ServiceInstalled() bool                               { return false }
func StartService() error                                  { return errNoService }
func CurrentUser() (string, error)                         { return "", errNoService }
func InstallerUserDataDir() (string, error)                { return UserDataDir() }
