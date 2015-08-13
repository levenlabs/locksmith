package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/levenlabs/locksmith/cfssl"
	"github.com/levenlabs/locksmith/config"
	"github.com/levenlabs/locksmith/ovpn"
	"io/ioutil"
	"log"
	"net/http"
)

type OVPNContents struct {
	CA []byte
}

func main() {
	log.Printf("Listening on %s", config.InternalAPIAddr)

	http.HandleFunc("/generate", generateHandler)
	log.Fatal(http.ListenAndServe(config.InternalAPIAddr, nil))
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %s %s %s", r.Method, r.RemoteAddr, r.RequestURI)
	if r.Method != "POST" {
		http.Error(w, "Invalid HTTP Method", http.StatusMethodNotAllowed)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		http.Error(w, "Invalid POST Body", http.StatusBadRequest)
		return
	}
	if len(config.HMACKey) > 0 {
		sig := r.URL.Query().Get("sig")
		if sig == "" {
			http.Error(w, "Invalid Request", http.StatusBadRequest)
			return
		}
		rawSig, err := hex.DecodeString(sig)
		if err != nil {
			http.Error(w, "Invalid Request", http.StatusBadRequest)
			return
		}
		if !verifyHMAC(body, rawSig) {
			http.Error(w, "Invalid HMAC Sig", http.StatusBadRequest)
			return
		}
	}
	var c cfssl.GenerateRequest
	err = json.Unmarshal(body, &c)
	if err != nil {
		http.Error(w, "Invalid POST Body", http.StatusBadRequest)
		return
	}
	cert, key, err := cfssl.GenerateCert(&c, r.RemoteAddr)
	if err != nil {
		log.Printf("cfssl.GenerateCert(%#v) -> %s", c, err)
		http.Error(w, "Invalid Request", http.StatusBadRequest)
		return
	}
	err = ovpn.CreateWrite(w, cert, key)
	if err != nil {
		log.Printf("ovpn.CreateWrite -> %s", err)
		http.Error(w, "Error creating ovpn file", http.StatusInternalServerError)
		return
	}
	log.Printf("Generated: %s %s", c.Hostname, r.RemoteAddr)
}

func verifyHMAC(body []byte, sentMac []byte) bool {
	mac := hmac.New(sha256.New, config.HMACKey)
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(sentMac, expectedMAC)
}
