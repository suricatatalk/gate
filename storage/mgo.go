package storage

import (
	"time"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type MgoDataStorage struct {
	ConnectionString string
	Database         string
	tokens           string
	mgoSession       *mgo.Session
	mgoDB            *mgo.Database
	mgoTokens        *mgo.Collection
}

func NewMgoStorage() *MgoDataStorage {
	return &MgoDataStorage{
		ConnectionString: "localhost:27017",
		Database:         "surikata_auth",
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
	a.mgoTokens = a.mgoDB.C(a.tokens)

	return nil
}

func (a *MgoDataStorage) CloseSession() {
	a.mgoSession.Close()
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
