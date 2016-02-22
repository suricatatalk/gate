package storage

import (
	"time"

	"github.com/satori/go.uuid"
	"github.com/suricatatalk/gate/jwt"
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

// DataStorage provides the interface to handle basic Open/Close
// operations on various instances of storage (e.g. Redis,Mongo...)
type DataStorage interface {
	TokenStorage
	// OpenSession opens the session for storage.
	OpenSession() error
	// CloseSession closes the connection to storage. After this method is called,
	// the communication with storage shoudl
	// not be available without the OpenSession call.
	CloseSession()
}

// TokenStorage serves as the interface to handle
// token chaching in api gateway "gate" microservice.
type TokenStorage interface {
	// TokenByEmail(email string) (Token, error)
	TokenByRefToken(tknString string) (Token, error)
	// InvalidateAllByEmail(tknString string) error
	InsertToken(tkn Token) error
}

// NewToken creates new instance of Token struct with
// given jwtToken, generated new value of "reference token"
func NewToken(user auth.User, jwtToken string) (Token, error) {
	token := Token{}
	jwtToken, err := jwt.GenerateJwtToken(user)
	if err != nil {
		return token, err
	}
	token.Id = bson.NewObjectId()
	token.JwtToken = jwtToken
	token.Email = user.Email
	token.RefToken = uuid.NewV4().String()
	token.Expiration = time.Now().Add(time.Hour * 72).Unix()
	return token, nil
}
