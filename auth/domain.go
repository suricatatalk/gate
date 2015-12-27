package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/satori/go.uuid"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var (
	ErrUserAlreadyExist = errors.New("User already exist")
)

//User structure
//to hold user data
type User struct {
	Id              bson.ObjectId `bson:"_id"`
	UserID          string
	Email           string
	Password        string
	Expiration      int64
	LastAccess      int64
	Activated       bool
	ActivationToken string
}

func (user User) Equals(other *User) bool {
	match := user.Email == other.Email
	match = match && user.Password == other.Password
	match = match && user.Expiration == other.Expiration
	match = match && user.LastAccess == other.LastAccess
	return match
}

func NewInactiveUser() User {
	user := User{
		Activated:       false,
		ActivationToken: uuid.NewV4().String(),
	}
	return user
}

//Creates the user from given map.
//Generally to use with JWT token decoding
func NewUser(m map[string]interface{}) (*User, error) {
	//TODO rewrite to non-ugly
	user := &User{}
	mId, ok := m["Id"]
	if ok {
		user.Id = bson.ObjectId(mId.(string))
	}
	email, emailok := m["Email"]
	if emailok {
		user.Email = email.(string)
	}
	pass, passOk := m["Password"]
	if passOk {
		user.Password = pass.(string)
	}
	exp, expOk := m["Expiration"]
	if expOk {

		user.Expiration = int64(exp.(float64))
	}
	access, accessOk := m["LastAccess"]
	if accessOk {

		user.LastAccess = int64(access.(float64))
	}
	return user, nil
}

type Token struct {
	Id         bson.ObjectId `bson:"_id"`
	Email      string
	RefToken   string
	JwtToken   string
	Expiration int64
}

func NewToken(user User, jwtToken string) Token {
	token := Token{}
	token.JwtToken = jwtToken
	token.Email = user.Email
	token.RefToken = uuid.NewV4().String()
	token.Expiration = time.Now().Add(time.Hour * 72).Unix()
	return token
}

type DataStorage interface {
	OpenSession() error
	CloseSession()
	InsertUser(user User) error
	UpdateUser(user User) error
	DeleteUser(userId string) error
	ActivateUser(activationToken string) error
	UserByEmail(email string) (User, error)
	TokenByEmail(email string) (Token, error)
	TokenByRefToken(tknString string) (Token, error)
	InvalidateAllByEmail(tknString string) error
	InsertToken(tkn Token) error
}

type MgoDataStorage struct {
	ConnectionString string
	Database         string
	users            string
	tokens           string
	mgoSession       *mgo.Session
	mgoDB            *mgo.Database
	mgoUsers         *mgo.Collection
	mgoTokens        *mgo.Collection
}

func NewMgoStorage() *MgoDataStorage {
	return &MgoDataStorage{
		ConnectionString: "localhost:27017",
		Database:         "surikata_auth",
		users:            "users",
		tokens:           "tokens",
	}

}

func (a *MgoDataStorage) OpenSession() error {
	var err error
	a.mgoSession, err = mgo.Dial(a.ConnectionString)
	if err != nil {
		return err
	}
	a.mgoDB = a.mgoSession.DB(a.Database)
	a.mgoUsers = a.mgoDB.C(a.users)
	a.mgoTokens = a.mgoDB.C(a.tokens)

	a.mgoUsers.EnsureIndex(mgo.Index{
		Key:        []string{"email"},
		Unique:     true,
		Background: true,
	})
	return nil
}

func (a *MgoDataStorage) CloseSession() {
	a.mgoSession.Close()
}

func (a *MgoDataStorage) InsertUser(user User) error {
	user.Id = bson.NewObjectId()
	err := a.mgoUsers.Insert(&user)
	if err != nil && strings.Contains(err.Error(), "E11000 duplicate key") {
		return ErrUserAlreadyExist
	}
	return err
}

func (a *MgoDataStorage) UpdateUser(user User) error {
	return a.mgoUsers.Update(bson.M{"email": user.Email}, &user)
}

func (a *MgoDataStorage) DeleteUser(email string) error {
	return a.mgoUsers.Remove(bson.M{"email": email})
}

func (a *MgoDataStorage) ActivateUser(activationToken string) error {
	return a.mgoUsers.Update(bson.M{"activationtoken": activationToken},
		bson.M{"$set": bson.M{"activated": true, "activationtoken": ""}})
}

func (a *MgoDataStorage) UserByEmail(email string) (User, error) {
	user := User{}
	err := a.mgoUsers.Find(bson.M{"email": email}).One(&user)
	if user.Email != email {
		return user, err
	}
	return user, err
}

func (a *MgoDataStorage) InsertToken(token Token) error {
	token.Id = bson.NewObjectId()
	return a.mgoTokens.Insert(&token)
}

func (a *MgoDataStorage) TokenByEmail(email string) (Token, error) {
	tkn := Token{}
	err := a.mgoTokens.Find(bson.M{"email": email}).Sort("-expiration").One(&tkn)
	return tkn, err
}

func (a *MgoDataStorage) TokenByRefToken(tknString string) (Token, error) {
	tkn := Token{}
	err := a.mgoTokens.Find(bson.M{"reftoken": tknString}).One(&tkn)
	return tkn, err
}

func (a *MgoDataStorage) InvalidateAllByEmail(email string) error {
	_, err := a.mgoTokens.UpdateAll(bson.M{"email": email}, bson.M{"$set": bson.M{"expiration": time.Now().Unix()}})
	return err
}
