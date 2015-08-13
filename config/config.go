// Package config parses command-line/environment/config file arguments and puts
// together the configuration of this instance, which is made available to other
// packages.
package config

import "github.com/mediocregopher/lever"

// Configurable variables which are made available
var (
	InternalAPIAddr  string
	HMACKey          []byte
	OVPNTemplateFile string
	CAFile           string
	CFSSLAddr        string
	CFSSLKey         string
	DefaultNameFile  string
	TimestampDrift   float64
)

func init() {
	l := lever.New("locksmith", nil)
	l.Add(lever.Param{
		Name:        "--internal-addr",
		Description: "Address to listen on for the internal api",
		Default:     ":8889",
	})
	l.Add(lever.Param{
		Name:        "--key",
		Description: "HMAC key for incoming requests",
		Default:     "",
	})
	l.Add(lever.Param{
		Name:        "--ovpn-template",
		Description: "Template file for ovpn output",
		Default:     "./ovpn.template",
	})
	l.Add(lever.Param{
		Name:        "--ca-file",
		Description: "CA file (if you have a bundle, this should be the bundle)",
		Default:     "",
	})
	l.Add(lever.Param{
		Name:        "--cfssl-addr",
		Description: "Address to cfssl server",
		Default:     "127.0.0.1:8888",
	})
	l.Add(lever.Param{
		Name:        "--cfssl-auth",
		Description: "Auth Key to create certificates in cfssl",
		Default:     "",
	})
	l.Add(lever.Param{
		Name:        "--default-name-file",
		Description: "Default name params in a json file",
		Default:     "",
	})
	l.Add(lever.Param{
		Name:        "--timestamp-drift",
		Description: "Maximum allowed timestamp drift in seconds (0 to disable checking)",
		Default:     "10",
	})
	l.Parse()

	InternalAPIAddr, _ = l.ParamStr("--internal-addr")
	k, _ := l.ParamStr("--key")
	HMACKey = []byte(k)
	OVPNTemplateFile, _ = l.ParamStr("--ovpn-template")
	CAFile, _ = l.ParamStr("--ca-file")
	CFSSLAddr, _ = l.ParamStr("--cfssl-addr")
	CFSSLKey, _ = l.ParamStr("--cfssl-auth")
	DefaultNameFile, _ = l.ParamStr("--default-name-file")
	td, _ := l.ParamInt("--timestamp-drift")
	TimestampDrift = float64(td)
}
