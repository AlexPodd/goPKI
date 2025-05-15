package main

import (
	"crypto/rand"
	"crypto/sha256"
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
		EmailAddresses:        csr.EmailAddresses,
	}

	template.DNSNames = csr.DNSNames
	template.IPAddresses = csr.IPAddresses

	if len(ca.cert.SubjectKeyId) == 0 {
		pubBytes, err := x509.MarshalPKIXPublicKey(ca.cert.PublicKey)
		if err == nil {
			sum := sha256.New().Sum(pubBytes)
			ca.cert.SubjectKeyId = sum[:]
		}
	}

	template.AuthorityKeyId = ca.cert.SubjectKeyId
	certificate, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.privateKey)

	return template, certificate, err
}

func (ca *certificateAutor) canUse() bool {
	if err := ca.cert.CheckSignatureFrom(ca.rootCA); err != nil {
		log.Print(err.Error())
		return false
	}

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
			if !cas.IsCA {
				return nil, errors.New("issuer is not a CA")
			}
			if cas.KeyUsage&x509.KeyUsageCertSign == 0 {
				return nil, errors.New("issuer cannot sign certificates (missing KeyUsageCertSign)")
			}
			if err := user.CheckSignatureFrom(cas); err != nil {
				return nil, errors.New("подпись недействительна: %v" + err.Error())
			}
			return cas, nil
		}
	}
	return nil, errors.New("issuer not found")
}
