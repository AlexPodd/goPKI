package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

func (app *application) ocspCheck(req []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	ocspURL := "https://localhost:8081/application/ocsp-request"
	httpResp, err := http.Post(ocspURL, "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		app.errorLog.Print(err)
		return nil, err
	}
	defer httpResp.Body.Close()

	ocspRespBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		app.errorLog.Print(err)
		return nil, err
	}

	return ocsp.ParseResponse(ocspRespBytes, issuer)
}

func (app *application) ocsp_server(w http.ResponseWriter, r *http.Request) {
	reqBytes, err := io.ReadAll(r.Body)
	var respBytes []byte

	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	ocspReq, err := ocsp.ParseRequest(reqBytes)

	app.infoLog.Print(ocspReq.SerialNumber.String())
	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, "Failed to parse body", http.StatusBadRequest)
		return
	}

	exist, err := app.revoked_certificates.FindSerial(*ocspReq.SerialNumber)

	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, "Failed to check revoke", http.StatusBadRequest)
		return
	}

	if exist {
		respBytes, err = createOCSPResponceInRevoked(app, ocspReq)
		if err != nil {
			app.errorLog.Print(err)
			http.Error(w, "Failed to check revoke", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
		return
	}
	status, err := app.certificates.FindForSerialOCSP(*ocspReq.SerialNumber)

	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, "Failed to check revoke", http.StatusBadRequest)
		return
	}

	if status == ocsp.Revoked {
		respBytes, err = createOCSPResponceInRevoked(app, ocspReq)
		if err != nil {
			app.errorLog.Print(err)
			http.Error(w, "Failed to check revoke", http.StatusBadRequest)
			return
		}
	} else {
		respBytes, err = createOCSPResponce(app, ocspReq, status)
	}

	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, "Failed to check revoke", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func (app *application) findIsUserOCSP(alg crypto.Hash, nameHash, keyHash []byte) (*certificateAutor, error) {
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	app.infoLog.Printf(
		"Searching CA: alg=%s, nameHash=%x, keyHash=%x",
		alg.String(), nameHash, keyHash,
	)
	for _, cas := range app.cas {
		h1 := alg.New()
		h1.Write(cas.cert.RawSubject)
		calculatedNameHash := h1.Sum(nil)

		asn1.Unmarshal(cas.cert.RawSubjectPublicKeyInfo, &publicKeyInfo)
		h2 := alg.New()
		h2.Write(publicKeyInfo.PublicKey.RightAlign())
		calculatedKeyHash := h2.Sum(nil)

		app.infoLog.Printf(
			"CA '%s': nameHash=%x, keyHash=%x",
			cas.cert.Subject.CommonName,
			calculatedNameHash,
			calculatedKeyHash,
		)

		if bytes.Equal(calculatedNameHash, nameHash) && bytes.Equal(calculatedKeyHash, keyHash) {
			return cas, nil
		}
	}
	return nil, errors.New("issuer not found")
}

func createOCSPResponceInRevoked(app *application, ocspReq *ocsp.Request) ([]byte, error) {
	time_revoke, reason, err := app.revoked_certificates.FindTimeAndReason(*ocspReq.SerialNumber)

	if err != nil {
		return nil, err
	}

	resp := ocsp.Response{
		Status:           ocsp.Revoked,
		SerialNumber:     ocspReq.SerialNumber,
		ThisUpdate:       time.Now(),
		NextUpdate:       time.Now().Add(24 * time.Hour),
		RevokedAt:        time_revoke,
		RevocationReason: reason,
	}
	isUserCA, err := app.findIsUserOCSP(ocspReq.HashAlgorithm, ocspReq.IssuerNameHash, ocspReq.IssuerKeyHash)

	if err != nil {
		return nil, err
	}

	respByte, err := ocsp.CreateResponse(isUserCA.cert, isUserCA.cert, resp, isUserCA.privateKey)

	if err != nil {
		return nil, err
	}

	return respByte, nil
}

func createOCSPResponce(app *application, ocspReq *ocsp.Request, status int) ([]byte, error) {
	resp := ocsp.Response{
		Status:       status,
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	isUserCA, err := app.findIsUserOCSP(ocspReq.HashAlgorithm, ocspReq.IssuerNameHash, ocspReq.IssuerKeyHash)
	if err != nil {
		return nil, err
	}

	respByte, err := ocsp.CreateResponse(isUserCA.cert, isUserCA.cert, resp, isUserCA.privateKey)

	if err != nil {
		return nil, err
	}

	return respByte, nil
}

func (app *application) secure(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<html><body><h1>доступ получен</h1></body></html>"))
}

type serialRequest struct {
	Serial string `json:"serial"`
}

func (app *application) ocsp_server_serial(w http.ResponseWriter, r *http.Request) {
	var req serialRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	bigInt := new(big.Int)
	_, ok := bigInt.SetString(req.Serial, 10)
	if !ok {
		http.Error(w, "Serial number is corrupt", http.StatusUnauthorized)
		return
	}
	exist, err := app.revoked_certificates.FindSerial(*bigInt)
	if err != nil {
		unkwownOrError(err, w, app)
		return
	}
	if exist {
		ocspRevoked(w, app, req.Serial)
		return
	}

	cert, err := app.certificates.FindForSerialCertificate(*bigInt)
	if err != nil {
		unkwownOrError(err, w, app)
		return
	}

	block, _ := pem.Decode([]byte(cert))
	if block == nil || block.Type != "CERTIFICATE" {
		app.errorLog.Print(err)
		http.Error(w, "Error parsing certificate", http.StatusUnauthorized)
		return
	}

	clientCert, err := x509.ParseCertificate(block.Bytes)

	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, "Error parsing certificate", http.StatusUnauthorized)
		return
	}

	isUser, err := app.cas[0].findIsUser(clientCert)
	if isUser == nil || err != nil {
		app.errorLog.Print(err)
		http.Error(w, "Unknown certificate issuer", http.StatusUnauthorized)
		return
	}

	ocspreq, err := ocsp.CreateRequest(clientCert, isUser, &ocsp.RequestOptions{
		Hash: crypto.SHA256,
	})

	if ocspreq == nil || err != nil {
		app.errorLog.Print(err)
		http.Error(w, "OCSP check failed", http.StatusUnauthorized)
		return
	}

	ocspResp, err := app.ocspCheck(ocspreq, isUser)
	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, "Certificate revoked or OCSP check failed", http.StatusUnauthorized)
		return

	}
	writeOCSPResponce(ocspResp, req, w)
}

func writeOCSPResponce(ocspResp *ocsp.Response, req serialRequest, w http.ResponseWriter) {
	response := struct {
		Serial    string `json:"serial"`
		OCSP      string `json:"OCSP"`
		Status    string `json:"status"`
		Timestamp string `json:"timestamp"`
	}{
		Serial:    req.Serial,
		OCSP:      ocspStatus(ocspResp.Status), // Преобразуем статус в строку
		Status:    "success",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
}

func unkwownOrError(err error, w http.ResponseWriter, app *application) {
	app.errorLog.Print(err)
	if err == sql.ErrNoRows {
		response := struct {
			OCSP string `json:"OCSP"`
		}{
			OCSP: ocspStatus(ocsp.Unknown),
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			app.errorLog.Print(err)
			http.Error(w, "Error encoding responce", http.StatusUnauthorized)
			return
		}
		return
	}

	http.Error(w, "Error parsing certificate", http.StatusUnauthorized)
}

func ocspRevoked(w http.ResponseWriter, app *application, serial string) {
	response := struct {
		Serial    string `json:"serial"`
		OCSP      string `json:"OCSP"`
		Timestamp string `json:"timestamp"`
	}{
		Serial:    serial,
		OCSP:      ocspStatus(ocsp.Revoked),
		Timestamp: time.Now().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, "Error encoding responce", http.StatusUnauthorized)
		return
	}
	return
}

func ocspStatus(status int) string {
	switch status {
	case 0:
		return "good"
	case 1:
		return "revoked"
	case 2:
		return "unknown"
	}
	return ""
}
