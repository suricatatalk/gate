package auth

import (
	"errors"
	"log"
	"strings"
	"time"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var (
	ErrUserAlreadyExist = errors.New("User already exist")
)

//User structure
//to hold user data
type User struct {
	Id         bson.ObjectId
	Email      string
	Password   string
	Expiration int64
	LastAccess int64
}

func (user User) Equals(other *User) bool {
	match := user.Email == other.Email
	match = match && user.Password == other.Password
	match = match && user.Expiration == other.Expiration
	match = match && user.LastAccess == other.LastAccess
	return match
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
	Id         bson.ObjectId
	Email      string
	RefToken   string
	JwtToken   string
	Expiration int64
}

type DataStorage interface {
	OpenSession() error
	CloseSession()
	InsertUser(user *User) error
	UpdateUser(user *User) error
	DeleteUser(userId string) error
	UserByEmail(email string) (*User, error)
	TokenByEmail(email string) (*Token, error)
	TokenByRefToken(tknString string) (*Token, error)
	InvalidateAllByEmail(tknString string) error
	InsertToken(tkn *Token) error
}

type MgoDataStorage struct {
	connectionString string
	database         string
	users            string
	tokens           string
	mgoSession       *mgo.Session
	mgoDB            *mgo.Database
	mgoUsers         *mgo.Collection
	mgoTokens        *mgo.Collection
}

func NewMgoStorage() *MgoDataStorage {
	return &MgoDataStorage{
		connectionString: "localhost:27017",
		database:         "surikata_auth",
		users:            "users",
		tokens:           "sessions",
	}

}

func NewMgoStorageConnectionAndDatabase(connString, database string) *MgoDataStorage {
	return &MgoDataStorage{
		connectionString: "localhost:27017",
		database:         "surikata_auth",
		users:            "users",
		tokens:           "sessions",
	}

}

func (a *MgoDataStorage) OpenSession() error {
	var err error
	a.mgoSession, err = mgo.Dial(a.connectionString)
	if err != nil {
		return err
	}
	a.mgoDB = a.mgoSession.DB(a.database)
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

func (a *MgoDataStorage) InsertUser(user *User) error {
	err := a.mgoUsers.Insert(user)
	if err != nil && strings.Contains(err.Error(), "E11000 duplicate key") {
		return ErrUserAlreadyExist
	}
	return err
}

func (a *MgoDataStorage) UpdateUser(user *User) error {
	return a.mgoUsers.Update(bson.M{"email": user.Email}, user)
}

func (a *MgoDataStorage) DeleteUser(email string) error {
	return a.mgoUsers.Remove(bson.M{"email": email})
}

func (a *MgoDataStorage) UserByEmail(email string) (*User, error) {
	user := &User{}
	err := a.mgoUsers.Find(bson.M{"email": email}).One(user)
	if user.Email != email {
		return nil, err
	}
	return user, err
}

func (a *MgoDataStorage) InsertToken(token *Token) error {
	return a.mgoTokens.Insert(token)
}

func (a *MgoDataStorage) TokenByEmail(email string) (*Token, error) {
	tkn := &Token{}
	err := a.mgoTokens.Find(bson.M{"email": email}).One(tkn)
	if tkn.Email == "" {
		tkn = nil
	}
	return tkn, err
}

func (a *MgoDataStorage) TokenByTokenString(tknString string) (*Token, error) {
	tkn := &Token{}
	err := a.mgoTokens.Find(bson.M{"refToken": tknString}).One(tkn)
	return tkn, err
}

func (a *MgoDataStorage) InvalidateAllByEmail(email string) error {
	changeInfo, err := a.mgoTokens.UpdateAll(bson.M{"email": email}, bson.M{"$set": bson.M{"expiration": time.Now().Unix()}})
	log.Println(changeInfo)
	return err
}
