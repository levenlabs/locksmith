// Package cfssl handles talking to cfssl server
package cfssl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/levenlabs/locksmith/config"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"regexp"
	"time"
)

var defaultName *csrName
var defaultKey *csrKey

type csrKey struct {
	Algo string `json:"algo"`
	Size uint   `json:"size"`
}

type csrName struct {
	C  string
	ST string
	L  string
	O  string
	OU string
}

//csrRequest is in a GenerateRequest and a certRequest
type csrRequest struct {
	CN    string    `json:"CN,omitempty"`
	Hosts []string  `json:"hosts"`
	Key   csrKey    `json:"key,omitempty"`
	Names []csrName `json:"names"`
}

//certRequest is sent to cfssl server
type certRequest struct {
	Hostname      string     `json:"hostname"`
	Request       csrRequest `json:"request"`
	Profile       string     `json:"profile,omitempty"`
	RemoteAddress string     `json:"remoteAddress"`
	Token         string     `json:"token,omitempty"`
	Timestamp     int64      `json:"timestamp,omitempty"`
}

//cfsslResult is what we get from cfssl
type cfsslResult struct {
	Success bool                   `json:"success"`
	Result  map[string]interface{} `json:"result"`
	Errors  []interface{}          `json:"errors,omitempty"`
}

type GenerateRequest struct {
	Hostname  string     `json:"hostname"`
	Request   csrRequest `json:"request"`
	Profile   string     `json:"profile,omitempty"`
	Timestamp int64      `json:"timestamp,omitempty"`
}

func init() {
	if config.CFSSLAddr == "" {
		log.Fatal("--cfssl-addr must be sent")
	}

	if config.DefaultNameFile != "" {
		defaultName = &csrName{}
		c, err := ioutil.ReadFile(config.DefaultNameFile)
		if err != nil {
			log.Fatal(err)
		}
		if err = json.Unmarshal(c, defaultName); err != nil {
			log.Fatal(err)
		}
	}

	defaultKey = &csrKey{"rsa", 2048}
}

func GenerateCert(req *GenerateRequest, remoteAddr string) (cert string, key string, err error) {
	if req.Hostname == "" {
		err = errors.New("Invalid hostname sent")
		return
	}
	if config.TimestampDrift > 0 {
		now := time.Now().UTC().Unix()
		diff := math.Abs(float64(now - req.Timestamp))
		if diff > config.TimestampDrift {
			err = errors.New("Timestamp sent is outside of drift range")
			return
		}
	}
	// we can't check if Key == nil because Key isn't a pointer but we can check for size not existing
	if req.Request.Key.Size == 0 {
		req.Request.Key = *defaultKey
	}
	if req.Request.CN == "" {
		req.Request.CN = req.Hostname
	}
	if req.Request.Names == nil {
		req.Request.Names = []csrName{*defaultName}
	} else if len(req.Request.Names) == 0 {
		req.Request.Names = append(req.Request.Names, *defaultName)
	}
	if req.Request.Hosts == nil {
		req.Request.Hosts = []string{req.Hostname}
	} else if len(req.Request.Hosts) == 0 {
		req.Request.Hosts = append(req.Request.Hosts, req.Hostname)
	}
	r := certRequest{}
	r.Hostname = req.Hostname
	r.Request = req.Request
	r.Profile = req.Profile
	r.RemoteAddress = remoteAddr
	r.Token = config.CFSSLKey
	r.Timestamp = req.Timestamp

	j, err := json.Marshal(r)
	if err != nil {
		return
	}
	res, err := request("/api/v1/cfssl/newcert", j)
	if err != nil {
		return
	}

	var ok bool
	if cert, ok = res.Result["certificate"].(string); !ok {
		err = fmt.Errorf("Missing certificate from newcert req %v", res.Result)
		return
	}

	if key, ok = res.Result["private_key"].(string); !ok {
		err = fmt.Errorf("Missing private_key from newcert req %v", res.Result)
		return
	}
	return
}

func request(path string, req []byte) (*cfsslResult, error) {
	url := config.CFSSLAddr + path
	if matched, _ := regexp.Match("/^https?://.*", []byte(url)); !matched {
		url = "http://" + url
	}
	r, err := http.NewRequest("POST", url, bytes.NewBuffer(req))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	d := json.NewDecoder(res.Body)
	var cr cfsslResult
	err = d.Decode(&cr)
	if err != nil {
		return nil, err
	}
	if !cr.Success {
		return nil, fmt.Errorf("Errors requesting cfssl %v", cr.Errors)
	}
	return &cr, nil
}
