// Package ovpn handles creating a ovpn file
package ovpn

import (
	"github.com/levenlabs/locksmith/config"
	"io"
	"io/ioutil"
	"log"
	"text/template"
)

var ovpnTemplate *template.Template
var caContents string

type ovpnVars struct {
	CA   string
	Cert string
	Key  string
}

func init() {
	var err error
	ovpnTemplate, err = template.ParseFiles(config.OVPNTemplateFile)
	if err != nil {
		log.Fatal(err)
	}

	if config.CAFile != "" {
		c, err := ioutil.ReadFile(config.CAFile)
		if err != nil {
			log.Fatal(err)
		}
		caContents = string(c)
	} else {
		log.Printf("Warning: no --ca-file specified so {{.CA}} will not be replaced")
	}
}

func CreateWrite(w io.Writer, cert string, key string) error {
	vars := &ovpnVars{
		caContents,
		cert,
		key,
	}
	return ovpnTemplate.Execute(w, vars)
}
