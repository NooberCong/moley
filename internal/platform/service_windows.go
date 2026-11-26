package platform

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceName is the Windows service (and systemd unit) name.
const ServiceName = "Moley"

// RunService runs run under the service control manager when this process
// was started by it, and reports whether it was. Stop and shutdown
// requests cancel run's context.
func RunService(run func(ctx context.Context) error) (bool, error) {
	if ok, err := svc.IsWindowsService(); err != nil || !ok {
		return false, err
	}
	h := &serviceHandler{run: run}
	if err := svc.Run(ServiceName, h); err != nil {
		return true, err
	}
	return true, h.err
}

type serviceHandler struct {
	run func(ctx context.Context) error
	err error
}

func (h *serviceHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	var giveUp <-chan time.Time // set once a stop is asked for
	for {
		select {
		case h.err = <-done:
			status <- svc.Status{State: svc.StopPending}
			if h.err != nil {
				return true, 1 // a failure: the SCM's recovery actions restart it
			}
			return false, 0
		case <-giveUp:
			// The core didn't close in time (a tunnel stuck tearing down).
			// Exiting frees its adapter and sockets; staying would leave the
			// service "stopping" for good, so an upgrade could never start.
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 10000}
				cancel()
				if giveUp == nil {
					giveUp = time.After(10 * time.Second)
				}
			}
		}
	}
}

// InstallService registers exe as the Moley service: LocalSystem, started
// at boot, restarted on failure, with a service SID (the kill switch's
// firewall filters match it). The users in allow may start and stop it
// and use its control pipe.
func InstallService(exe string, allow []string) error {
	m, err := mgr.Connect()
	if err != nil {
		return elevationHint(err)
	}
	defer m.Disconnect()
	args := []string{"service", "--system"}
	for _, sid := range allow {
		args = append(args, "--allow", sid)
	}
	cfg := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS, // UpdateConfig, unlike CreateService, doesn't default it
		DisplayName:  "Moley",
		Description:  "Routes this computer's traffic through your VPNs and proxies, by your rules.",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	s, err := m.OpenService(ServiceName)
	if err == nil {
		// Reinstall (an upgrade): same name, new path and arguments.
		defer s.Close()
		cfg.BinaryPathName = windows.EscapeArg(exe)
		for _, a := range args {
			cfg.BinaryPathName += " " + windows.EscapeArg(a)
		}
		if err := s.UpdateConfig(cfg); err != nil {
			return err
		}
	} else {
		if s, err = m.CreateService(ServiceName, exe, cfg, args...); err != nil {
			return err
		}
		defer s.Close()
	}
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 2 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 60); err != nil {
		return err
	}
	// Default service permissions, plus start/stop/query for each user.
	sddl := "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
	for _, sid := range allow {
		sddl += "(A;;CCLCSWRPWPDTLOCRRC;;;" + sid + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(s.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// UninstallService stops and removes the service.
func UninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return elevationHint(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return SetKillSwitch("off", "") // not installed; lift a leftover block all the same
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err == nil {
			waitState(s, svc.Stopped, 20*time.Second)
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	return SetKillSwitch("off", "") // a persistent block outlives the service
}

// ServiceInstalled reports whether the service is registered.
func ServiceInstalled() bool {
	s, err := openService(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	windows.CloseServiceHandle(s)
	return true
}

// StartService starts the installed service and waits until it runs. It
// needs no elevation for a user the service was installed for.
func StartService() error {
	h, err := openService(windows.SERVICE_START | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	s := &mgr.Service{Name: ServiceName, Handle: h}
	defer s.Close()
	st, err := s.Query()
	if err == nil && st.State == svc.Running {
		return nil
	}
	if err == nil && st.State == svc.StopPending {
		// Still stopping (an upgrade's `sc stop` returns at once): a start
		// now would be refused as "already running".
		waitState(s, svc.Stopped, 20*time.Second)
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	if !waitState(s, svc.Running, 20*time.Second) {
		return errors.New("the Moley service did not start; see Event Viewer › Windows Logs › Application")
	}
	return nil
}

func openService(access uint32) (windows.Handle, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(ServiceName)
	return windows.OpenService(scm, name, access)
}

func waitState(s *mgr.Service, want svc.State, timeout time.Duration) bool {
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if st, err := s.Query(); err == nil && st.State == want {
			return true
		}
	}
	return false
}

func elevationHint(err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("%w: run this from an administrator terminal", err)
	}
	return err
}

// CurrentUser identifies the user running this process (a SID), for
// InstallService's allow list.
func CurrentUser() (string, error) { return currentUserSID() }

// InstallerUserDataDir is the per-user state of whoever is installing
// the service (an elevated process keeps the user's profile).
func InstallerUserDataDir() (string, error) { return UserDataDir() }
