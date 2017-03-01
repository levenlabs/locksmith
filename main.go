package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/levenlabs/locksmith/certs"
	"github.com/levenlabs/locksmith/cfssl"
	"github.com/levenlabs/locksmith/config"
	"github.com/levenlabs/locksmith/ocsp"
	"github.com/levenlabs/locksmith/ovpn"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"time"
)

type genericReq struct {
	Timestamp int64 `json:"timestamp,omitempty"`
}

type revokeReq struct {
	Certificate string `json:"certificate"`
	Reason      int    `json:"reason,omitempty"`
	Timestamp   int64  `json:"timestamp,omitempty"`
}

type OVPNContents struct {
	CA []byte
}

func main() {
	http.HandleFunc("/generate", generateHandler)
	http.HandleFunc("/list", listHandler)
	http.HandleFunc("/revoke", revokeHandler)

	if h := ocsp.GetHandler(); h != nil {
		http.Handle("/ocsp-verify", h)
	}

	log.Printf("Listening on %s", config.InternalAPIAddr)
	log.Fatal(http.ListenAndServe(config.InternalAPIAddr, nil))
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %s %s %s", r.Method, r.RemoteAddr, r.RequestURI)
	if r.Method != "POST" {
		http.Error(w, "Invalid HTTP Method", http.StatusMethodNotAllowed)
		return
	}
	body := readAndVerifyBody(w, r, "generate", config.HMACKey)
	if body == nil {
		return
	}

	var c cfssl.GenerateRequest
	err := json.Unmarshal(body, &c)
	if err != nil {
		http.Error(w, "Invalid POST Body", http.StatusBadRequest)
		return
	}
	if !verifyTimestamp(w, c.Timestamp) {
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Printf("net.SplitHostPort(%s) -> %s", r.RemoteAddr, err)
		http.Error(w, "Invalid RemoteAddr", http.StatusBadRequest)
		return
	}

	cert, key, err := cfssl.GenerateCert(&c, ip)
	if err != nil {
		log.Printf("cfssl.GenerateCert(%#v) -> %s", c, err)
		http.Error(w, "Invalid Request", http.StatusBadRequest)
		return
	}

	err = certs.SaveCert(c.Hostname, ip, cert)
	if err != nil {
		log.Printf("SaveCert error: %s", err)
		http.Error(w, "Error saving certificate file", http.StatusInternalServerError)
		return
	}

	if config.AutoOCSP {
		ocspReq := &cfssl.OCSPSignRequest{
			Certificate: cert,
			Status:      "good",
		}
		resp, err := cfssl.SignOCSPResponse(ocspReq)
		if err != nil {
			log.Printf("SignOCSPResponse error: %s", err)
			http.Error(w, "Error signing ocsp response", http.StatusInternalServerError)
			return
		}
		err = ocsp.RecordNewResponse(resp)
		if err != nil {
			log.Printf("RecordNewResponse error: %s", err)
			http.Error(w, "Error recording ocsp response", http.StatusInternalServerError)
			return
		}
	}

	err = ovpn.CreateWrite(w, cert, key)
	if err != nil {
		log.Printf("ovpn.CreateWrite -> %s", err)
		http.Error(w, "Error creating ovpn file", http.StatusInternalServerError)
		return
	}
	log.Printf("Generated: %s %s", c.Hostname, ip)
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %s %s %s", r.Method, r.RemoteAddr, r.RequestURI)
	if r.Method != "POST" {
		http.Error(w, "Invalid HTTP Method", http.StatusMethodNotAllowed)
		return
	}
	body := readAndVerifyBody(w, r, "list", config.HMACAdminKey)
	if body == nil {
		return
	}

	var c genericReq
	err := json.Unmarshal(body, &c)
	if err != nil {
		http.Error(w, "Invalid POST Body", http.StatusBadRequest)
		return
	}
	if !verifyTimestamp(w, c.Timestamp) {
		return
	}

	certs := certs.ListCerts()
	resp, err := json.Marshal(certs)
	if err != nil {
		log.Printf("json.Marshal -> %s", err)
		http.Error(w, "Error creating json response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func revokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %s %s %s", r.Method, r.RemoteAddr, r.RequestURI)
	if r.Method != "POST" {
		http.Error(w, "Invalid HTTP Method", http.StatusMethodNotAllowed)
		return
	}
	body := readAndVerifyBody(w, r, "list", config.HMACAdminKey)
	if body == nil {
		return
	}

	var c revokeReq
	err := json.Unmarshal(body, &c)
	if err != nil {
		http.Error(w, "Invalid POST Body", http.StatusBadRequest)
		return
	}
	if !verifyTimestamp(w, c.Timestamp) {
		return
	}

	cert := c.Certificate
	// try to base64 decode the certificate first
	decoded, err := base64.StdEncoding.DecodeString(cert)
	if err == nil {
		cert = string(decoded)
	}

	// make sure the certificate is in PEM format
	p, _ := pem.Decode([]byte(cert))
	if p == nil {
		// since it wasn't in PEM format, put it in PEM format
		cert = string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte(cert),
		}))
	}

	now := time.Now()
	ocspReq := &cfssl.OCSPSignRequest{
		Certificate: cert,
		Status:      "revoked",
		Reason:      c.Reason,
		RevokedAt:   now.Format("2006-01-02"),
	}
	resp, err := cfssl.SignOCSPResponse(ocspReq)
	if err != nil {
		log.Printf("SignOCSPResponse revoke error: %s", err)
		http.Error(w, "Error signing ocsp response", http.StatusInternalServerError)
		return
	}
	err = ocsp.RecordNewResponse(resp)
	if err != nil {
		log.Printf("RecordNewResponse revoke error: %s", err)
		http.Error(w, "Error recording ocsp response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{\"success\":true}"))
}

func readAndVerifyBody(w http.ResponseWriter, r *http.Request, method string, key []byte) []byte {
	// the body is optional since they can make GET requests
	body, err := ioutil.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		http.Error(w, "Invalid POST Body", http.StatusBadRequest)
		return nil
	}
	if len(key) > 0 {
		sig := r.URL.Query().Get("sig")
		if sig == "" {
			http.Error(w, "Invalid Request", http.StatusBadRequest)
			return nil
		}
		if !verifyHMAC(method, body, sig, key) {
			http.Error(w, "Invalid HMAC Sig", http.StatusBadRequest)
			return nil
		}
	}
	return body
}

func verifyHMAC(method string, body []byte, sentSig string, key []byte) bool {
	rawSig, err := hex.DecodeString(sentSig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(rawSig, expectedMAC)
}

func verifyTimestamp(w http.ResponseWriter, ts int64) bool {
	if config.TimestampDrift > 0 {
		now := time.Now().UTC().Unix()
		diff := math.Abs(float64(now - ts))
		if diff > config.TimestampDrift {
			http.Error(w, "Timestamp sent is outside of drift range", http.StatusBadRequest)
			return false
		}
	}
	return true
}
