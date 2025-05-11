package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
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

func (app *application) ocsp_server_serial(w http.ResponseWriter, r *http.Request) {
}
