package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
)

type reCreateCertRequest struct {
	Name      string `json:"username"`
	SignedCSR string `json:"csr"`
	Signature string `json:"signature"`
}

func (app *application) createNewCert(w http.ResponseWriter, r *http.Request) {
	var req reCreateCertRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	app.infoLog.Print(req.Name)
	app.infoLog.Print(req.SignedCSR)
	app.infoLog.Print(req.Signature)

	clientCert, err := app.certificates.FindForCN(req.Name)
	if err != nil {
		http.Error(w, "certificate not found", http.StatusBadRequest)
		return
	}

	rsaPubKey, ok := clientCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		app.errorLog.Fatalf("not an RSA public key")
		http.Error(w, "not an RSA public key", http.StatusBadRequest)
		return
	}

	err = VerifySignature(rsaPubKey, req.SignedCSR, req.Signature, app)

	if err != nil {
		app.errorLog.Print("private key dont match")
		http.Error(w, "private key dont match", http.StatusBadRequest)
		return
	}

	app.revoked_certificates.Revoke(*clientCert.SerialNumber, 4)
	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, "err while otziv", http.StatusBadRequest)
		return
	}

	app.certificates.DeleteForCN(req.Name)
	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, "err while delete", http.StatusBadRequest)
		return
	}

	block, _ := pem.Decode([]byte(req.SignedCSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "Invalid PEM CSR", http.StatusBadRequest)
		return
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, "Invalid CSR", http.StatusBadRequest)
		return
	}

	if csr.CheckSignature() != nil {
		app.errorLog.Print(err)
		http.Error(w, "Ошибка создания csr", http.StatusBadRequest)
		return
	}

	for _, ca := range app.cas {
		if !ca.canUse() {
			continue
		}
		bdCert, cert, err := ca.createCertificate(csr)

		if err != nil {
			app.errorLog.Print(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

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

func VerifySignature(pubKey *rsa.PublicKey, data string, base64Sig string, app *application) error {

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	sigBytes, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed, sigBytes)
	app.errorLog.Print(err)
	app.infoLog.Printf("Signing with data: [%x]\n", data)
	app.infoLog.Printf("Hash: [%x]\n", sha256.Sum256([]byte(data)))
	app.infoLog.Printf("Signature base64: %s\n", base64.StdEncoding.EncodeToString(sigBytes))
	if err != nil {
		return errors.New("signature verification failed")
	}
	return nil
}
