package models

import (
	"database/sql"
	"errors"  // New import
	"strings" // New import
	"time"

	"github.com/go-sql-driver/mysql"
)

// Define a new User type. Notice how the field names and types align
// with the columns in the database "users" table?
type User struct {
	ID      int
	Name    string
	Created time.Time
}

type UserModel struct {
	DB *sql.DB
}

func (m *UserModel) Insert(name string) error {
	stmt := `INSERT INTO users (username, created_at) VALUES(?, UTC_TIMESTAMP())`
	_, err := m.DB.Exec(stmt, name)
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

// We'll use the Exists method to check if a user exists with a specific ID.
func (m *UserModel) Exists(id int) (bool, error) {
	var exists bool
	stmt := "SELECT EXISTS(SELECT true FROM users WHERE id = ?)"
	err := m.DB.QueryRow(stmt, id).Scan(&exists)
	return exists, err
}

func (m *UserModel) UserExists(username string) (int, error) {
	var id int

	stmt := "SELECT id FROM users WHERE username = ?"
	err := m.DB.QueryRow(stmt, username).Scan(id)

	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}

	return id, err
}

func (m *UserModel) DeleteUser(userID int) (bool, error) {
	stmt := `DELETE FROM users WHERE id = ?`
	result, err := m.DB.Exec(stmt, userID)
	if err != nil {
		return false, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	if rowsAffected > 0 {
		return true, nil
	}
	return false, nil
}
