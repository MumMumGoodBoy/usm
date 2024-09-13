package model

import (
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	UserName  string `gorm:"uniqueIndex"`
	Email     string `gorm:"uniqueIndex"`
	Password  string
	FirstName string
	LastName  string
	IsAdmin   bool
}

type RegisterUserInput struct {
	UserName  string `json:"userName"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type LoginUserInput struct {
	UserName string `json:"userName"`
	Password string `json:"password"`
}

type JWTClaims struct {
	jwt.RegisteredClaims
	UserId  uint `json:"userId"`
	IsAdmin bool `json:"isAdmin"`
}
