package jwt

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/suricatatalk/guardian/auth"
	"golang.org/x/crypto/bcrypt"
)

const (
	JwtUserKey = "user"
	JwtExpKey  = "exp"
	JwtSecret  = "12345678901234567890123456789012"
)

var (
	ErrUserExpired              = errors.New("User identity expired")
	ErrPasswordNotMatch         = errors.New("Password not match")
	ErrUserNotFound             = errors.New("User not found")
	ErrCannotRetrieveExpiration = errors.New("Cannot retireve expiration from token")
	ErrTokenExpired             = errors.New("Token expired")
	ErrResetTokenExpired        = errors.New("Reset token expired")
	ErrNoPasswordResetRequested = errors.New("No password request")
)

func GenerateJwtToken(user auth.User) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims[JwtUserKey] = user
	token.Claims[JwtExpKey] = time.Now().Add(time.Hour * 72).Unix()
	return token.SignedString([]byte(JwtSecret))
}

// DecodeJwtToken validate
// and decode the JWT token
func DecodeJwtToken(token string) (*auth.User, error) {
	outToken, err := jwt.Parse(token, func(tkn *jwt.Token) (interface{}, error) {
		expirate, ok := tkn.Claims[JwtExpKey].(float64)
		if !ok {
			return nil, ErrCannotRetrieveExpiration
		}
		if expirate < float64(time.Now().Unix()) {
			return nil, ErrTokenExpired
		}
		return []byte(JwtSecret), nil
	})
	if err == nil && outToken.Valid {
		tokenMap := outToken.Claims[JwtUserKey].(map[string]interface{})
		user, err := auth.NewUser(tokenMap)
		return user, err
	}
	return nil, err
}

func verifyUser(user auth.User, password string) error {
	if user.Email == "" {
		return ErrUserNotFound
	}
	if !(user.Expiration < time.Now().Unix()) {
		return ErrUserExpired
	}
	passOk := comparePasswordHash(user.Password, password)
	if !passOk {
		return ErrPasswordNotMatch
	}
	return nil
}

func comparePasswordHash(passHash, plainpassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(passHash), []byte(plainpassword))
	if err != nil {
		return false
	}
	return true
}
