package models

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/ocsp"
)

type Certificate struct {
	ID           int
	UserName     string
	SerialNumber big.Int
	validFrom    time.Time
	validTo      time.Time
	Certificate  string
}

type CertificateModel struct {
	DB *sql.DB
}

func (m *CertificateModel) Insert(username string, serial big.Int, validFrom time.Time, validTo time.Time, certificate string) error {
	stmt := `INSERT INTO certificates (username, serial_number, valid_from, valid_to, certificate) VALUES(?, ?, ? ,?,?)`
	_, err := m.DB.Exec(stmt, username, serial.String(), validFrom, validTo, certificate)
	if err != nil {
		var mySQLError *mysql.MySQLError
		if errors.As(err, &mySQLError) {
			if mySQLError.Number == 1062 && strings.Contains(mySQLError.Message, "users.username") {
				return ErrUserExist
			}
		}
		return err
	}
	return nil
}

func (m *CertificateModel) FindForSerialCertificate(serial big.Int) (string, error) {
	serialStr := serial.String()

	var certificate string
	query := `SELECT certificate FROM certificates WHERE serial_number = ?`

	err := m.DB.QueryRow(query, serialStr).Scan(&certificate)
	if err != nil {
		return certificate, err
	}

	return certificate, nil
}

func (m *CertificateModel) FindForCN(CN string) (*x509.Certificate, error) {
	var certificate string
	query := `SELECT certificate FROM certificates WHERE username = ?`
	err := m.DB.QueryRow(query, CN).Scan(&certificate)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, err
	}

	clientCert, err := x509.ParseCertificate(block.Bytes)

	if err != nil {
		return nil, err
	}
	return clientCert, nil
}

func (m *CertificateModel) DeleteForCN(CN string) error {
	query := `DELETE FROM certificates WHERE username = ?`
	_, err := m.DB.Exec(query, CN)
	return err
}

func (m *CertificateModel) FindForSerialOCSP(serial big.Int) (int, error) {
	serialStr := serial.String()

	var validTo time.Time
	query := `SELECT valid_to FROM certificates WHERE serial_number = ?`

	err := m.DB.QueryRow(query, serialStr).Scan(&validTo)
	if err == sql.ErrNoRows {
		return ocsp.Unknown, nil
	}
	if err != nil {
		return -1, err
	}

	if time.Now().After(validTo) {
		revokeQuery := `INSERT INTO revoked_certificates (cert_id, revoked_at, reason) VALUES (?, ?, ?)`
		_, err := m.DB.Exec(revokeQuery, serialStr, time.Now(), ocsp.Revoked)
		if err != nil {
			return -1, err
		}
		return ocsp.Revoked, nil
	}

	return ocsp.Good, nil
}
