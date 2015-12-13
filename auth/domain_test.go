package auth

import (
	"log"
	"testing"
	"time"

	"gopkg.in/mgo.v2/bson"
)

func cleanUp(store *MgoDataStorage) {
	store.mgoDB.DropDatabase()
	store.CloseSession()
}

func createMgoStorage() *MgoDataStorage {
	mongo := NewMgoStorage()
	mongo.Database = "surikata_test"
	mongo.OpenSession()
	return mongo
}

func TestInsertUser(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}
	err := mongo.InsertUser(user)
	if err != nil {
		t.Error(err)
	}
	count, err := mongo.mgoUsers.Count()
	if err == nil && count != 1 {
		t.Error("User not inserted")
	}

}

func TestInsertMultiple(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}

	err := mongo.InsertUser(user)
	if err != nil {
		t.Error(err)
	}
	err = mongo.InsertUser(user)
	if err == nil {
		t.Error("Unique index not working")
	}

}

func TestUserByEmail(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}
	err := mongo.InsertUser(user)
	if err != nil {
		t.Error(err)
	}
	count, err := mongo.mgoUsers.Count()
	if err == nil && count != 1 {
		t.Error("User not inserted")
	}
	userByEmail, userByMailErr := mongo.UserByEmail(user.Email)
	if userByMailErr != nil {
		log.Println(userByMailErr)
		t.Error("Error selecting user")
		return
	}

	match := user.Equals(&userByEmail)
	if !match {
		t.Error("Users not match")
	}
}

func TestDeleteUser(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}
	err := mongo.InsertUser(user)
	if err != nil {
		t.Error(err)
	}
	count, err := mongo.mgoUsers.Count()
	if err == nil && count != 1 {
		t.Error("User not inserted")
	}
	mongo.DeleteUser(user.Email)
	count, err = mongo.mgoUsers.Count()
	if err == nil && count != 0 {
		t.Error("User not deleted")
	}
}

func TestInsertToken(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}
	tokenString, tokenErr := generateJwtToken(user)
	if tokenErr != nil {
		t.Error(tokenErr)
	}

	//TODO create token and short token
	token := Token{}
	token.JwtToken = tokenString
	token.Email = user.Email
	token.RefToken = "1234"
	token.Expiration = time.Now().Add(time.Hour * 72).Unix()
	err := mongo.InsertToken(token)
	if err != nil {
		t.Error(err)
		return
	}
	count, err := mongo.mgoTokens.Count()
	if err == nil && count != 1 {
		t.Error("Token not inserted")
		return
	}
}

func TestTokenByEmail(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}
	tokenString, tokenErr := generateJwtToken(user)
	if tokenErr != nil {
		t.Error(tokenErr)
	}

	//TODO create token and short token
	token := Token{}
	token.JwtToken = tokenString
	token.Email = user.Email
	token.RefToken = "1234"
	token.Expiration = time.Now().Add(time.Hour * 72).Unix()
	err := mongo.InsertToken(token)
	if err != nil {
		t.Error(err)
		return
	}
	selToken, selErr := mongo.TokenByEmail(user.Email)
	if selErr != nil && selToken.RefToken == token.RefToken {
		t.Error(selErr)
		return
	}
	selToken, selErr = mongo.TokenByRefToken(token.RefToken)
	if selErr != nil {
		t.Error(selErr)
		return
	}
	if selToken.JwtToken != token.JwtToken {
		t.Error("Token not match")
	}
}

func TestInvalidateToken(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}
	tokenString, tokenErr := generateJwtToken(user)
	if tokenErr != nil {
		t.Error(tokenErr)
	}

	//TODO create token and short token
	token := Token{}
	token.JwtToken = tokenString
	token.Email = user.Email
	token.RefToken = "1234"
	token.Expiration = time.Now().Add(time.Hour * 72).Unix()
	err := mongo.InsertToken(token)
	if err != nil {
		t.Error(err)
		return
	}
	count, err := mongo.mgoTokens.Count()
	if err == nil && count != 1 {
		t.Error("Token not inserted")
		return
	}

	mongo.InvalidateAllByEmail(token.Email)
	selToken, selErr := mongo.TokenByRefToken(token.RefToken)
	if selErr != nil {
		t.Error(selErr)
		return
	}

	now := time.Now()

	if !(selToken.Expiration <= now.Unix()) {
		log.Printf("Expiration %d now is %d", selToken.Expiration, now.Unix())
		t.Error("Token not updated")
	}

}

func TestActivateUser(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:              bson.NewObjectId(),
		Email:           "sohlich@example.com",
		Password:        "ABCDEF",
		Expiration:      time.Now().Unix(),
		LastAccess:      time.Now().Unix(),
		ActivationToken: "12345",
		Activated:       false,
	}
	err := mongo.InsertUser(user)
	if err != nil {
		t.Error(err)
	}
	count, err := mongo.mgoUsers.Count()
	if err == nil && count != 1 {
		t.Error("User not inserted")
	}
	mongo.ActivateUser(user.ActivationToken)
	dbUser, _ := mongo.UserByEmail(user.Email)
	if !dbUser.Activated {
		t.Error("User not activated")
	}
}
