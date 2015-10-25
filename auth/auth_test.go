package auth

import (
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
	user := &User{
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
