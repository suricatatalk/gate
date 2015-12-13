package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

const (
	JwtUserKey = "user"
	JwtExpKey  = "exp"
	JwtSecret  = "12345678901234567890123456789012"
)

var (
	ErrUserExpired      = errors.New("User identity expired")
	ErrPasswordNotMatch = errors.New("Password not match")
	ErrUserNotFound     = errors.New("User not found")
)

type AuthClient interface {
	DecodeToken(token string) (User, error)
}

type AuthBouncer interface {
	ValueToReferenceToken(token string)
	ReferenceToValueToken(token string)
}

type AuthProvider interface {
	SignUp(user User) error
	SignIn(email, password string) (string, error)
	SignOut(refToken string) error
	// ReferenceToken(email string) (string, error)
	ValueToken(refToken string) (string, error)
	ActivateUser(activationToken string) error
}

//Authenticator provide
//simple authentication
//API.
type AuthServer interface {
	SignUp(rw http.ResponseWriter, req *http.Request)
	SignIn(rw http.ResponseWriter, req *http.Request)
	Logout(rw http.ResponseWriter, req *http.Request)
	Verify(rw http.ResponseWriter, req *http.Request)
}

type MgoAuthProvider struct {
	store DataStorage
}

func (m *MgoAuthProvider) SignUp(user User) error {
	var err error
	user.Password, err = encryptPassword(user.Password)
	err = m.store.InsertUser(user)
	return err
}

func (m *MgoAuthProvider) SignIn(email, password string) (string, error) {
	now := time.Now()
	user, err := m.store.UserByEmail(email)
	if err != nil {
		return "", err
	}
	err = verifyUser(user, password)

	token, _ := m.store.TokenByEmail(email)
	if token.Email != "" && token.Expiration < now.Unix() {
		return token.RefToken, nil
	}

	tokenString, tokenErr := generateJwtToken(user)

	if tokenErr != nil {
		return "", tokenErr
	}

	//TODO create token and short token
	token = NewToken(user, tokenString)
	err = m.store.InsertToken(token)
	if err != nil {
		return "", err
	}
	return token.RefToken, err
}

func (m *MgoAuthProvider) SignOut(refToken string) error {
	token, err := m.store.TokenByRefToken(refToken)
	if err != nil {
		return err
	}
	m.store.InvalidateAllByEmail(token.Email)
	return nil
}

func (m *MgoAuthProvider) ValueToken(refToken string) (string, error) {
	token, err := m.store.TokenByRefToken(refToken)
	if err != nil && token.Email != "" {
		return "", err
	} else {
		tokenString := token.JwtToken
		return tokenString, nil
	}
}

func (m *MgoAuthProvider) ActivateUser(activationToken string) error {
	return m.ActivateUser(activationToken)
}

func NewAuthProvider(store DataStorage) *MgoAuthProvider {
	provider := &MgoAuthProvider{
		store,
	}
	return provider
}

func comparePasswordHash(passHash, plainpassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(passHash), []byte(plainpassword))
	if err != nil {
		return false
	}
	return true
}

func encryptPassword(password string) (string, error) {
	bcrOut, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	output := string(bcrOut)
	return output, err
}

func generateJwtToken(user User) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims[JwtUserKey] = user
	token.Claims[JwtExpKey] = time.Now().Add(time.Hour * 72).Unix()
	return token.SignedString([]byte(JwtSecret))
}

func DecodeJwtToken(token string) (*User, error) {
	outToken, err := jwt.Parse(token, func(tkn *jwt.Token) (interface{}, error) {
		expirate, ok := tkn.Claims[JwtExpKey].(float64)
		if !ok || expirate < float64(time.Now().Unix()) {
			return nil, jwt.ErrInvalidKey
		}
		return []byte(JwtSecret), nil
	})
	if err == nil && outToken.Valid {
		tokenMap := outToken.Claims[JwtUserKey].(map[string]interface{})
		user, err := NewUser(tokenMap)
		return user, err
	} else {
		return nil, err
	}

}

func verifyUser(user User, password string) error {
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
