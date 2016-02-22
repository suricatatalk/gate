package storage

import (
	"testing"
	"time"

	"gopkg.in/mgo.v2/bson"

	"github.com/suricatatalk/gate/jwt"
	"github.com/suricatatalk/guardian/auth"
)

var testUser = auth.User{
	bson.NewObjectId(),
	"12345",
	"test@example.com",
	"password",
	time.Now().Unix(),
	time.Now().Unix(),
	true,
}

func TestNewToken(t *testing.T) {
	jwtToken, err := jwt.GenerateJwtToken(testUser)
	if err != nil {
		t.Error(err)
	}
	token, _ := NewToken(testUser, jwtToken)

	if token.Email != testUser.Email {
		t.Error("Token not created properly")
	}
}

func TestMarshallUnmarshalBinary(t *testing.T) {

	jwtToken, err := jwt.GenerateJwtToken(testUser)
	if err != nil {
		t.Error(err)
	}
	token, _ := NewToken(testUser, jwtToken)

	serialized, tokenErr := token.MarshalBinary()
	if tokenErr != nil {
		t.Error(tokenErr)
	}

	deserializedToken := &Token{}
	deserializedToken.UnmarshalBinary(serialized)

	if token.JwtToken != deserializedToken.JwtToken {
		t.Error("Token do not serialize properly")
	}

}
