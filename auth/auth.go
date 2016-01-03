package auth

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	JwtUserKey = "user"
	JwtExpKey  = "exp"
	JwtSecret  = "12345678901234567890123456789012"
)

// Secrutity activtity
const (
	PASSWORD_RESET = "PASSWORD_RESET"
)

var (
	ErrUserExpired              = errors.New("User identity expired")
	ErrPasswordNotMatch         = errors.New("Password not match")
	ErrUserNotFound             = errors.New("User not found")
	ErrCannotRetrieveExpiration = errors.New("Cannot retireve expiration from token")
	ErrTokenExpired             = errors.New("Token expired")
	ErrNoPasswordResetRequested = errors.New("No password request")
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
	ValueToken(refToken string) (string, error)
	ActivateUser(activationToken string) error
}

type PasswordManager interface {
	RequestPasswordResetFor(email string) (string, error)
	ResetPasswordBy(token, newpass string) error
}

//Authenticator provider
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
	if err != nil {
		return "", err
	}

	// m.store.InvalidateAllByEmail(email)
	token, _ := m.store.TokenByEmail(email)
	if token.Email != "" && token.Expiration > now.Unix() {
		return token.RefToken, nil
	}

	tokenString, tokenErr := generateJwtToken(user)

	if tokenErr != nil {
		return "", tokenErr
	}

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
	return m.store.ActivateUser(activationToken)
}

func (m *MgoAuthProvider) RequestPasswordResetFor(email string) (string, error) {

	now := time.Now()
	user, err := m.store.UserByEmail(email)
	if err != nil {
		return "", err
	}

	activity := &Activity{
		Type:       PASSWORD_RESET,
		Token:      uuid.NewV4().String(),
		Time:       now.Unix(),
		User:       user.Id.Hex(),
		Expiration: now.Add(24 * time.Hour).Unix(),
	}
	err = m.store.InsertActivity(activity)

	if err != nil {
		return "", nil
	}
	return activity.Token, nil
}

func (m *MgoAuthProvider) ResetPasswordBy(activityToken, newpass string) error {
	activity, err := m.store.GetActivityByToken(activityToken)
	if err != nil {
		return err
	}

	if len(activity.Token) == 0 || activity.Type != PASSWORD_RESET {
		return ErrNoPasswordResetRequested
	}

	var user User
	user, err = m.store.UserByID(activity.User)
	if len(user.Email) == 0 {
		return ErrUserNotFound
	}

	encPass, encErr := encryptPassword(newpass)
	if encErr != nil {
		return encErr
	}
	user.Password = encPass
	return m.store.UpdateUser(user)
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

// DecodeJwtToken validate
// and decode the JWT token
func DecodeJwtToken(token string) (*User, error) {
	outToken, err := jwt.Parse(token, func(tkn *jwt.Token) (interface{}, error) {
		expirate, ok := tkn.Claims[JwtExpKey].(float64)
		if !ok {
			return nil, ErrCannotRetrieveExpiration
		}
		log.Printf("Expiration %f", expirate)
		if expirate < float64(time.Now().Unix()) {
			return nil, ErrTokenExpired
		}
		return []byte(JwtSecret), nil
	})
	if err == nil && outToken.Valid {
		tokenMap := outToken.Claims[JwtUserKey].(map[string]interface{})
		user, err := NewUser(tokenMap)
		return user, err
	}
	return nil, err
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
