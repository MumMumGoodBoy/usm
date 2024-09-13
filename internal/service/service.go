package service

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mummumgoodboy/usm/internal/model"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserService struct {
	db     *gorm.DB
	signer crypto.PrivateKey
}

func NewUserService(db *gorm.DB, jwtKey string) (*UserService, error) {
	key, err := jwt.ParseEdPrivateKeyFromPEM([]byte(jwtKey))
	if err != nil {
		return nil, fmt.Errorf("error while parsing jwt key: %w", err)
	}
	return &UserService{
		db:     db,
		signer: key,
	}, nil
}

func (u *UserService) RegisterUser(user model.RegisterUserInput) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error while hashing password: %w", err)
	}
	// check if email already exists
	var count int64
	err = u.db.Model(&model.User{}).Where("email = ?", user.Email).Count(&count).Error
	if err != nil {
		return fmt.Errorf("error while checking email: %w", err)
	}
	if count > 0 {
		return ErrEmailExists
	}

	err = u.db.Model(&model.User{}).Where("user_name = ?", user.UserName).Count(&count).Error
	if err != nil {
		return fmt.Errorf("error while checking username: %w", err)
	}
	if count > 0 {
		return ErrUserExists
	}

	newUser := model.User{
		UserName:  user.UserName,
		Email:     user.Email,
		Password:  hex.EncodeToString(hashedPassword),
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}

	err = u.db.Create(&newUser).Error
	if err != nil {
		return fmt.Errorf("error while creating new user: %w", err)
	}

	return nil
}

func (u *UserService) LoginUser(user model.LoginUserInput) (string, error) {
	var foundUser model.User
	err := u.db.Where("user_name = ?", user.UserName).First(&foundUser).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("username not found: %w", ErrWrongCredentials)
		}
		return "", fmt.Errorf("error while finding user: %w", err)
	}
	byteUserPassword, err := hex.DecodeString(foundUser.Password)
	if err != nil {
		return "", fmt.Errorf("error while decoding password: %w", err)
	}

	err = bcrypt.CompareHashAndPassword(byteUserPassword, []byte(user.Password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return "", fmt.Errorf("wrong password: %w", ErrWrongCredentials)
		}
		return "", fmt.Errorf("error while comparing password: %w", err)
	}

	claim := model.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "user-management-service",
			Subject:   foundUser.UserName,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		},
		UserId:  foundUser.ID,
		IsAdmin: foundUser.IsAdmin,
	}

	token, err := u.signJWTToken(claim)
	if err != nil {
		return "", fmt.Errorf("error while signing token while login: %w", err)
	}

	return token, nil
}

func (u *UserService) signJWTToken(claim model.JWTClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claim)
	token, err := t.SignedString(u.signer)
	if err != nil {
		return "", fmt.Errorf("error while signing token: %w", err)
	}
	return token, nil
}

// GetUsersById returns users by their ids.
// The index of the returned slice are not guaranteed to be the same as the input ids.
// The returned slice can be smaller than the input ids if some ids are not found.
func (u *UserService) GetUsersById(ids []uint) ([]model.User, error) {
	var users []model.User
	err := u.db.Find(&users, ids).Error
	if err != nil {
		return nil, fmt.Errorf("error while getting users by id: %w", err)
	}
	return users, nil
}
