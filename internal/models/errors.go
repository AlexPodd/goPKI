package models

import (
	"errors"
)

var (
	ErrUserExist = errors.New("models: this name alredy exist")
	//ErrCSRSign = errors.New("models: csr sign is invalid")

	ErrNoRecord           = errors.New("models: no matching record found")
	ErrInvalidCredentials = errors.New("models: invalid credentials")
	ErrDuplicateEmail     = errors.New("models: duplicate email")

	ErrDuplicateCompanyName = errors.New("models: duplicate company name")

	ErrInvalidUserID = errors.New("models: invalid userID")

	ErrInvalidProjectName = errors.New("models: duplicate project")

	ErrInvalidTaskName = errors.New("models: duplicate task")

	ErrWrongTimeFormat = errors.New("models: wrong time format")

	ErrDuplicateNameInCompany = errors.New("models: duplicate user in company")

	TaskNotFound = errors.New("models: task not found")

	TaskIsAlredyDone = errors.New("models: task is done")
)
