package models

import (
	"database/sql"
	"math/big"
	"time"
)

type RevockeCertificate struct {
	ID      int
	cert_id big.Int
	revoked time.Time
	reason  int
}

type RevokedCertificateModel struct {
	DB *sql.DB
}

func (m *RevokedCertificateModel) FindSerial(serial big.Int) (bool, error) {
	serialStr := serial.String()
	var exists bool
	query := `SELECT EXISTS (SELECT 1 FROM revoked_certificates WHERE cert_id = ?)`

	err := m.DB.QueryRow(query, serialStr).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (m *RevokedCertificateModel) FindTimeAndReason(serial big.Int) (time.Time, int, error) {
	var revokedAt time.Time
	var reason int

	query := `
        SELECT revoked_at, reason
        FROM revoked_certificates
        WHERE cert_id = ?
    `
	row := m.DB.QueryRow(query, serial.String())

	err := row.Scan(&revokedAt, &reason)
	if err != nil {
		return time.Time{}, -1, err
	}

	return revokedAt, reason, nil
}
