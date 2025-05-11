package models

import (
	"database/sql"
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
