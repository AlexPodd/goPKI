package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
)

type csrRequest struct {
	CSR string `json:"csr"`
}

func (app *application) createCertificate(w http.ResponseWriter, r *http.Request) {
	var req csrRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "Invalid PEM CSR", http.StatusBadRequest)
		return
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, "Invalid CSR", http.StatusBadRequest)
		return
	}

	err = CheckSert(csr, app)
	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, ca := range app.cas {
		if !ca.canUse() {
			continue
		}
		bdCert, cert, err := ca.createCertificate(csr)

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})

		response := struct {
			Certificate string `json:"certificate"`
		}{
			Certificate: string(certPEM),
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)

		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			app.errorLog.Print("Error encoding response: ", err)
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
			return
		}

		err = app.users.Insert(csr.Subject.CommonName)
		err = app.certificates.Insert(bdCert.Subject.CommonName, *bdCert.SerialNumber, bdCert.NotBefore, bdCert.NotAfter, string(certPEM))
		if err != nil {
			app.errorLog.Print("Error encoding response: ", err)
			http.Error(w, "Error adding to DB", http.StatusInternalServerError)
			return
		}

		return
	}

	app.errorLog.Print("No avaible ca")
	http.Error(w, "No avaible ca", http.StatusBadRequest)
}

func CheckSert(csr *x509.CertificateRequest, app *application) error {
	if csr.CheckSignature() != nil {
		return errors.New("invalid CSR sign")
	}
	_, err := app.users.UserExists(csr.Subject.CommonName)

	if err != nil {
		return err
	}
	return nil
}
