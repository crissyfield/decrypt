package decrypt

import (
	"fmt"

	"github.com/frida/frida-go/frida"
	"github.com/go-viper/mapstructure/v2"
)

// Application represents an application installed on the device.
type Application struct {
	Identifier string // Identifier is the unique identifier of the application.
	Name       string // Name is the human-readable name of the application.
	Version    string // Version is the version of the application.
	Build      string // Build is the build number of the application.
	Path       string // Path is the file system path to the application.
}

// ListApplications retrieves all applications installed on the device.
func (dev *Device) ListApplications() ([]*Application, error) {
	// Enumerate applications
	apps, err := dev.device.EnumerateApplications("", frida.ScopeFull)
	if err != nil {
		return nil, fmt.Errorf("enumerate applications: %w", err)
	}

	var applications []*Application

	for _, app := range apps {
		// Get application parameters
		var params struct {
			Build      string            `mapstructure:"build"`
			Containers map[string]string `mapstructure:"containers"`
			Icons      struct {
				Format string  `mapstructure:"format"`
				Image  []uint8 `mapstructure:"image"`
			} `mapstructure:"icons"`
			Path    string `mapstructure:"path"`
			Version string `mapstructure:"version"`
		}

		err = mapstructure.Decode(app.Params(), &params)
		if err != nil {
			return nil, fmt.Errorf("decode application parameters: %w", err)
		}

		// Append application
		applications = append(applications, &Application{
			Identifier: app.Identifier(),
			Name:       app.Name(),
			Version:    params.Version,
			Build:      params.Build,
			Path:       params.Path,
		})
	}

	return applications, nil
}
