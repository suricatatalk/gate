package main

import (
	"log"
	"net/http"

	"github.com/sohlich/surikata/auth"
)

func main() {
	mgoStorage := auth.NewMgoStorage()
	err := mgoStorage.OpenSession()
	if err != nil {
		log.Panic(err)
	}

	http.ListenAndServe(":8080", nil)
}
