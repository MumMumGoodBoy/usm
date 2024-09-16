package service

import "fmt"

var (
	ErrWrongCredentials = fmt.Errorf("wrong credentials")
	ErrEmailExists      = fmt.Errorf("email already exists")
	ErrUserExists       = fmt.Errorf("user already exists")
	ErrNotFound         = fmt.Errorf("not found")
)
