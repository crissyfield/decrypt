package decrypt

import (
	"fmt"

	"github.com/frida/frida-go/frida"
)

// Script represents a Frida script loaded into a process.
type Script struct {
	session *frida.Session // The Frida process session.
	script  *frida.Script  // The loaded script.
}

// LoadScriptIntoProcess loads a Frida script into a specified process on the device.
func (dev *Device) LoadScriptIntoProcess(content string, processName string) (*Script, error) {
	// Attach to process
	session, err := dev.device.Attach(processName, nil)
	if err != nil {
		return nil, fmt.Errorf("attach to process [%s]: %w", processName, err)
	}

	// Create script
	script, err := session.CreateScript(content)
	if err != nil {
		return nil, fmt.Errorf("create script: %w", err)
	}

	// Load script into process
	if err := script.Load(); err != nil {
		return nil, fmt.Errorf("load script: %w", err)
	}

	return &Script{session: session, script: script}, nil
}

// Close cleans up script and session resources.
func (scr *Script) Close() {
	scr.script.Unload()  //nolint
	scr.session.Detach() //nolint
}

// Call invokes an exported function from the loaded script with the provided arguments.
func (scr *Script) Call(fn string, args ...any) any {
	return scr.script.ExportsCall(fn, args...)
}
