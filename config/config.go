// Package config parses command-line/environment/config file arguments and puts
// together the configuration of this instance, which is made available to other
// packages.
package config

import (
	"github.com/mediocregopher/lever"
)

// Configurable variables which are made available
var (
	InternalAPIAddr  string
	HMACKey          []byte
	HMACAdminKey     []byte
	OVPNTemplateFile string
	CAFile           string
	CFSSLAddr        string
	DefaultNameFile  string
	TimestampDrift   float64
	CertsFile        string
	OCSPRespFile     string
	AutoOCSP         bool
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
		Description: "HMAC key for incoming requests to /generate",
		Default:     "",
	})
	l.Add(lever.Param{
		Name:        "--admin-key",
		Description: "HMAC key for incoming requests to /revoke /list (defaults to --key)",
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
		Name:        "--default-name-file",
		Description: "Default name params in a json file",
		Default:     "",
	})
	l.Add(lever.Param{
		Name:        "--timestamp-drift",
		Description: "Maximum allowed timestamp drift in seconds (0 to disable checking)",
		Default:     "10",
	})
	l.Add(lever.Param{
		Name:        "--certs-file",
		Description: "Save/Read certificates to/from a file",
		Default:     "",
	})
	l.Add(lever.Param{
		Name:        "--ocsp-responses-file",
		Description: "OCSP responses file to serve from and update",
		Default:     "",
	})
	l.Add(lever.Param{
		Name:        "--auto-ocsp-sign",
		Description: "Automatically OCSP sign new certificates",
		Flag:        true,
	})
	l.Parse()

	InternalAPIAddr, _ = l.ParamStr("--internal-addr")
	k, _ := l.ParamStr("--key")
	HMACKey = []byte(k)
	HMACAdminKey = HMACKey
	k, _ = l.ParamStr("--admin-key")
	if len(k) > 0 {
		HMACAdminKey = []byte(k)
	}
	OVPNTemplateFile, _ = l.ParamStr("--ovpn-template")
	CAFile, _ = l.ParamStr("--ca-file")
	CFSSLAddr, _ = l.ParamStr("--cfssl-addr")
	DefaultNameFile, _ = l.ParamStr("--default-name-file")
	td, _ := l.ParamInt("--timestamp-drift")
	TimestampDrift = float64(td)
	CertsFile, _ = l.ParamStr("--certs-file")
	OCSPRespFile, _ = l.ParamStr("--ocsp-responses-file")
	AutoOCSP = l.ParamFlag("--auto-ocsp-sign")

}
