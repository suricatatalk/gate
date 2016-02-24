package storage

import (
	"testing"

	"github.com/suricatatalk/gate/jwt"
)

func TestRedisStorage(t *testing.T) {

	jwtToken, err := jwt.GenerateJwtToken(testUser)
	if err != nil {
		t.Error(err)
	}
	tkn, _ := NewToken(testUser, jwtToken)

	storage := NewRedisStorage()
	err = storage.OpenSession()
	if err != nil {
		t.Error(err)
	}

	err = storage.InsertToken(tkn)
	if err != nil {
		t.Error(err)
		return
	}

	loadedTkn, err := storage.TokenByRefToken(tkn.RefToken)
	if err != nil {
		t.Error(err)
		return
	}

	if loadedTkn.JwtToken != jwtToken {
		t.Error("Tokens not equal")
	}

}
