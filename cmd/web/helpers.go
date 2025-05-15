package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/youmark/pkcs8"
)

// The serverError helper writes an error message and stack trace to the errorLog,
// then sends a generic 500 Internal Server Error response to the user.
func (app *application) serverError(w http.ResponseWriter, err error) {

	http.Error(w, err.Error(), http.StatusInternalServerError)

	trace := fmt.Sprintf("%s\n%s", err.Error(), debug.Stack())
	app.errorLog.Output(2, trace)
}

func (app *application) ErrorHappen(w http.ResponseWriter, err error) {

	trace := fmt.Sprintf("%s\n%s", err.Error(), debug.Stack())
	app.errorLog.Output(2, trace)
}

func (app *application) isAuthenticated(r *http.Request) bool {
	return false
}

// The clientError helper sends a specific status code and corresponding description
// to the user. We'll use this later in the book to send responses like 400 "Bad
// Request" when there's a problem with the request that the user sent.
func (app *application) clientError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

func (app *application) notFound(w http.ResponseWriter) {
	app.clientError(w, http.StatusNotFound)
}

func LoadPrivateKeyFromFile(path string, password []byte) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block with private key")
	}

	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted private key: %v", err)
	}

	rsaPrivateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not an RSA private key")
	}

	return rsaPrivateKey, nil
}

func LoadCertificateFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block with certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func loadTrustCertificates(dir string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() || !(strings.HasSuffix(file.Name(), ".pem") || strings.HasSuffix(file.Name(), ".crt")) {
			continue
		}

		certPath := filepath.Join(dir, file.Name())
		cert, err := LoadCertificateFromFile(certPath)
		if err != nil {
			log.Printf("Не удалось загрузить сертификат из %s: %v", certPath, err)
			continue
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func loadConfig(filename string) (*AppConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var config AppConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func loadCAFromConfig(cfg *AppConfig, trust []*x509.Certificate) ([]*certificateAutor, error) {
	var cas []*certificateAutor

	for _, ca := range cfg.CAKeys {
		certPath := filepath.Join(cfg.TrustPath, ca.CertFile)
		keyPath := filepath.Join(cfg.KeyPath, ca.KeyFile)

		cert, err := LoadCertificateFromFile(certPath)
		if err != nil {
			log.Printf("Ошибка загрузки CA-сертификата %s: %v", certPath, err)
			continue
		}
		key, err := LoadPrivateKeyFromFile(keyPath, []byte(ca.Password))
		if err != nil {
			log.Printf("Ошибка загрузки ключа %s: %v", keyPath, err)
			continue
		}

		cas = append(cas, &certificateAutor{
			cert:               cert,
			privateKey:         key,
			trust:              trust,
			validateClientDate: cfg.ValidationDays,
		})
	}

	return cas, nil
}
