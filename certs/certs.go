// Package certs handles persisting and loading certs
package certs

import (
	"bufio"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/levenlabs/locksmith/config"
	"log"
	"os"
	"time"
)

type saveReq struct {
	Hostname    string
	RemoteAddr  string
	Certificate string
	ReplyCh     chan error
}

type Certificate struct {
	Hostname    string `json:"hostname"`
	RemoteAddr  string `json:"remoteAddr"`
	Generated   int64  `json:"generated_at"`
	Certificate string `json:"certificate"`
}

type listReq struct {
	ReplyCh chan []Certificate
}

var (
	listCh  = make(chan listReq)
	saveCh  = make(chan saveReq)
	timeFmt = "2006-01-02T15:04:05"
	fileFmt = "%s | %s | %s | %s"
)

func init() {
	if config.CertsFile != "" {
		// make sure we can write to the file
		f, err := os.OpenFile(config.CertsFile, os.O_CREATE, 0600)
		if err != nil {
			log.Fatalf("Failed to create certs file: %s", err)
		}
		f.Close()
	}

	go func() {
		var l listReq
		var s saveReq
		for {
			select {
			case l = <-listCh:
				l.ReplyCh <- listCerts()
			case s = <-saveCh:
				s.ReplyCh <- saveCert(s.Hostname, s.RemoteAddr, s.Certificate)
			}
		}
	}()
}

func SaveCert(hostname, remoteAddr, cert string) error {
	r := make(chan error)
	saveCh <- saveReq{
		Hostname:    hostname,
		RemoteAddr:  remoteAddr,
		Certificate: cert,
		ReplyCh:     r,
	}
	return <-r
}

func saveCert(hostname, remoteAddr, cert string) error {
	if config.CertsFile == "" {
		return nil
	}

	b, _ := pem.Decode([]byte(cert))
	if b == nil || len(b.Bytes) == 0 {
		return errors.New("Error reading PEM certificate")
	}

	b64cert := base64.StdEncoding.EncodeToString(b.Bytes)
	tf := time.Now().Format(timeFmt)
	line := fmt.Sprintf(fileFmt, tf, hostname, remoteAddr, b64cert)

	f, err := os.OpenFile(config.CertsFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	defer f.Close()
	line += "\n"
	if _, err = f.WriteString(line); err != nil {
		return err
	}
	return nil
}

func ListCerts() []Certificate {
	r := make(chan []Certificate)
	listCh <- listReq{
		ReplyCh: r,
	}
	return <-r
}

func listCerts() []Certificate {
	// give this some starting capacity
	c := make([]Certificate, 0, 16)
	if config.CertsFile == "" {
		return c
	}
	f, err := os.OpenFile(config.CertsFile, os.O_RDONLY, 0600)
	if err != nil {
		log.Printf("Error reading certs file: %s", err)
		return c
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	var l string
	var cert Certificate
	var t string
	var gen time.Time
	for s.Scan() {
		l = s.Text()
		if l == "" {
			continue
		}
		cert = Certificate{}
		_, err = fmt.Sscanf(l, fileFmt, &t, &cert.Hostname, &cert.RemoteAddr, &cert.Certificate)
		if err != nil {
			log.Printf("Error reading line from certs file: %s", err)
			continue
		}
		gen, err = time.Parse(timeFmt, t)
		if err != nil {
			log.Printf("Error parsing time in certs file: %s", err)
			continue
		}
		cert.Generated = gen.Unix()
		c = append(c, cert)
	}
	if err = s.Err(); err != nil {
		log.Printf("Error scanning certs file: %s", err)
	}
	return c
}
