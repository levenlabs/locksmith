// Package ocsp handles responding to ocsp requests and saving new ones
package ocsp

import (
	"github.com/levenlabs/locksmith/config"
	"log"

	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cloudflare/cfssl/ocsp"
	goocsp "golang.org/x/crypto/ocsp"
	"net/http"
	"os"
)

type recordReq struct {
	Response string
	ReplyCh  chan error
}

var responder *ocsp.Responder
var recordCh chan recordReq

func init() {
	if config.OCSPRespFile != "" {
		src, err := ocsp.NewSourceFromFile(config.OCSPRespFile)
		if err != nil {
			log.Fatalf("Failed to read ocsp responses file: %s", err)
		}
		responder = &ocsp.Responder{Source: src}
	}

	recordCh = make(chan recordReq)
	go func() {
		for req := range recordCh {
			req.ReplyCh <- recordNewResponse(req.Response)
		}
	}()
}

func GetHandler() http.Handler {
	if responder == nil {
		return nil
	}
	return *responder
}

func ReloadResponses() {
	src, err := ocsp.NewSourceFromFile(config.OCSPRespFile)
	if err != nil {
		log.Printf("Failed to reload ocsp responses file: %s", err)
		return
	}
	responder.Source = src
}

func RecordNewResponse(resp string) error {
	r := make(chan error)
	recordCh <- recordReq{
		Response: resp,
		ReplyCh:  r,
	}
	return <-r
}

func recordNewResponse(resp string) error {
	if responder == nil {
		return errors.New("No --ocsp-responses-file was sent cannot record new response")
	}
	//check to see if resp is base64 encoded or not
	decodedResp := []byte(resp)
	der, err := base64.StdEncoding.DecodeString(resp)
	if err == nil {
		decodedResp = der
	}

	r, err := goocsp.ParseResponse(decodedResp, nil)
	if err != nil {
		return err
	}

	src, ok := responder.Source.(ocsp.InMemorySource)
	if !ok {
		return errors.New("Could not typecast responder.Source to InMemorySource")
	}

	// from cfssl/ocsp/responder.go
	src[r.SerialNumber.String()] = decodedResp

	//encode to base64 before saving to responses file
	b64resp := base64.StdEncoding.EncodeToString(decodedResp)

	f, err := os.OpenFile(config.OCSPRespFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("Failed to open ocsp file to record new: %s", err)
		return err
	}

	defer f.Close()
	if _, err = f.WriteString(fmt.Sprint(b64resp, "\n")); err != nil {
		log.Printf("Failed to write to ocsp file to record new: %s", err)
		return err
	}
	return nil
}
