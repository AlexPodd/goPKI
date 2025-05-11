package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"os"
	"time"
)

func (ca *certificateAutor) createCertificate(csr *x509.CertificateRequest) (*x509.Certificate, []byte, error) {

	num, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	log.Printf("Generating cert: NotBefore=%v, NotAfter=%v (validity=%d days)",
		time.Now(),
		time.Now().AddDate(0, 0, ca.validateClientDate),
		ca.validateClientDate)
	template := &x509.Certificate{
		SerialNumber:          num,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, ca.validateClientDate),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: false,
		IsCA:                  false,
	}

	template.DNSNames = csr.DNSNames
	template.IPAddresses = csr.IPAddresses

	certificate, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.privateKey)

	return template, certificate, err
}

func (ca *certificateAutor) canUse() bool {
	return time.Until(ca.cert.NotAfter) >= time.Duration(ca.validateClientDate)*24*time.Hour
}

func SaveCertAsPEM(certDER []byte, filename string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	return os.WriteFile(filename, certPEM, 0644)
}

func generateSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 160)
	return rand.Int(rand.Reader, limit)
}

func (ca *certificateAutor) findIsUser(user *x509.Certificate) (*x509.Certificate, error) {
	for _, cas := range ca.trust {
		if user.Issuer.CommonName == cas.Subject.CommonName {
			// Если нашли совпадение с общим именем (CN), то это подходящий УЦ
			return cas, nil
		}
	}
	return nil, errors.New("issuer not found")
}
