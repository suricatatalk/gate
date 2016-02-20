package storage

import (
	"time"

	"github.com/satori/go.uuid"
	"github.com/suricatatalk/guardian/auth"
	"gopkg.in/mgo.v2/bson"
)

type Token struct {
	Id         bson.ObjectId `bson:"_id"`
	Email      string
	RefToken   string
	JwtToken   string
	Expiration int64
}

func (t Token) MarshalBinary() (data []byte, err error) {
	return bson.Marshal(t)
}

func (t *Token) UnmarshalBinary(data []byte) error {
	return bson.Unmarshal(data, t)
}

type DataStorage interface {
	TokenStorage
	OpenSession() error
	CloseSession()
}

type TokenStorage interface {
	// TokenByEmail(email string) (Token, error)
	TokenByRefToken(tknString string) (Token, error)
	// InvalidateAllByEmail(tknString string) error
	InsertToken(tkn Token) error
}

func NewToken(user auth.User, jwtToken string) Token {
	token := Token{}
	token.Id = bson.NewObjectId()
	token.JwtToken = jwtToken
	token.Email = user.Email
	token.RefToken = uuid.NewV4().String()
	token.Expiration = time.Now().Add(time.Hour * 72).Unix()
	return token
}
