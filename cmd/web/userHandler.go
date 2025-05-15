package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
)

type usernameRequest struct {
	Username string `json:"name"`
}

func (app *application) findUserInfo(w http.ResponseWriter, r *http.Request) {
	var req usernameRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	app.infoLog.Print(req.Username)
	clientCert, err := app.certificates.FindForCN(req.Username)

	if err != nil {
		app.errorLog.Print(err)
		if err == sql.ErrNoRows {
			response := struct {
				Status string `json:"status"`
			}{
				Status: "User not found",
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
		app.errorLog.Print(err)
		http.Error(w, "Error parsing certificate", http.StatusUnauthorized)
		return
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(clientCert.PublicKey)
	if err != nil {
		app.errorLog.Print(err)
		http.Error(w, "Error parsing public key", http.StatusBadRequest)
		return
	}

	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	email := ""
	if len(clientCert.EmailAddresses) > 0 {
		email = clientCert.EmailAddresses[0]
	} else {
		email = "not found"
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCert.Raw,
	})

	response := struct {
		Serial      string `json:"serial"`
		Email       string `json:"email"`
		Status      string `json:"status"`
		PublicKey   string `json:"publicKey"`
		Certificate string `json:"certificate"`
	}{
		Serial:      clientCert.SerialNumber.String(),
		Email:       email,
		Status:      "success",
		PublicKey:   string(pubKeyPem),
		Certificate: string(certPEM),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
}
