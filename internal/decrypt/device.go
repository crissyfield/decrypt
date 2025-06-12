package decrypt

import (
	"fmt"
	"sync"

	"github.com/frida/frida-go/frida"
	"github.com/go-viper/mapstructure/v2"
)

// Device represents a Frida device.
type Device struct {
	device frida.DeviceInt

	Access   string // Access can be "full" or "limited".
	Platform string // Platform can be "darwin", "linux", etc..
	Arch     string // Arch can be "arm64", "x86_64", etc..
	OS       string // OS can be "ios", "android", etc..
}

var (
	deviceManager     *frida.DeviceManager
	deviceManagerOnce sync.Once
)

// FindDevice returns the first available USB device that matches the criteria.
func FindDevice() (*Device, error) {
	// Initialize device manager, if not done already
	deviceManagerOnce.Do(func() {
		deviceManager = frida.NewDeviceManager()
	})

	if deviceManager == nil {
		return nil, fmt.Errorf("device manager unavailable")
	}

	// Find proper device
	devices, err := deviceManager.EnumerateDevices()
	if err != nil {
		return nil, fmt.Errorf("enumerate devices: %w", err)
	}

	var device frida.DeviceInt

	for _, dev := range devices {
		if dev.DeviceType() == frida.DeviceTypeUsb {
			device = dev
			break
		}
	}

	if device == nil {
		return nil, fmt.Errorf("no device found")
	}

	// Get device parameters
	var params struct {
		Access   string `mapstructure:"access"`
		Platform string `mapstructure:"platform"`
		Arch     string `mapstructure:"arch"`
		OS       struct {
			ID string `mapstructure:"id"`
		} `mapstructure:"os"`
	}

	ps, err := device.Params()
	if err != nil {
		return nil, fmt.Errorf("get device parameters: %w", err)
	}

	err = mapstructure.Decode(ps, &params)
	if err != nil {
		return nil, fmt.Errorf("decode device parameters: %w", err)
	}

	return &Device{
		device:   device,
		Access:   params.Access,
		Platform: params.Platform,
		Arch:     params.Arch,
		OS:       params.OS.ID,
	}, nil
}

// GetProcessID retrieves the process ID of a running application by its name.
func (dev *Device) GetProcessID(name string) (int, error) {
	// Enumerate processes
	processes, err := dev.device.EnumerateProcesses(frida.ScopeMetadata)
	if err != nil {
		return 0, fmt.Errorf("enumerate processes: %w", err)
	}

	// Find process by name
	for _, p := range processes {
		if p.Name() == name {
			return p.PID(), nil
		}
	}

	return 0, fmt.Errorf("process not found [%s]", name)
}
