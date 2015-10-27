package auth

import (
	"log"
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {

	secret := "secret"
	output, err := encryptPassword(secret)
	if err != nil {
		t.Errorf("Bcrypt failed %s", err)
	}

	if !comparePasswordHash(output, secret) {
		t.Error("Password not equal")
	}

}

func TestJwtToken(t *testing.T) {
	user := User{
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}

	token, err := generateJwtToken(user)
	if err != nil {
		t.Error(err)
		return
	}

	outputUser, decodeErr := decodeJwtToken(token)
	if decodeErr != nil {
		t.Error(decodeErr)
	}

	match := user.Equals(outputUser)
	if !match {
		t.Error("Users not match")
	}
}

func TestComplete(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	authProvider := NewAuthProvider(mongo)

	user := User{
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Add(72 * time.Hour).Unix(),
		LastAccess: time.Now().Unix(),
	}

	err := authProvider.SignUp(user)
	if err != nil {
		t.Error(err)
		t.Error("Couldnt sign up")
		return
	}

	refToken, signInErr := authProvider.SignIn(user.Email, "ABCDEF")
	if signInErr != nil {
		t.Error(signInErr)
		return
	}
	log.Println(refToken)

	if refToken == "" {
		t.Error("Token is empty")
	}

	token, valErr := authProvider.ValueToken(refToken)
	if valErr != nil {
		t.Error(valErr)
		return
	}
	log.Println(token)

	if token == "" {
		t.Error("Token is empty")
	}

	err = authProvider.SignOut(refToken)
	if err != nil {
		t.Error(err)
		return
	}
}
