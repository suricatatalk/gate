package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/sohlich/etcd_discovery"
	"github.com/sohlich/surikata_auth/auth"
)

const (
	TokenHeader = "X-AUTH"
)

var (
	ErrNoServiceInUrl                              = errors.New("No service definition in url")
	registryConfig    discovery.EtcdRegistryConfig = discovery.EtcdRegistryConfig{
		EtcdEndpoints: []string{"http://127.0.0.1:4001"},
		ServiceName:   "core",
		InstanceName:  "core1",
		BaseUrl:       "127.0.0.1:8080",
	}
	registryClient *discovery.EtcdReigistryClient
	authProvider   auth.AuthProvider
)

func main() {
	var registryErr error
	registryClient, registryErr = discovery.New(registryConfig)
	if registryErr != nil {
		log.Panic(registryErr)
	}
	mgoStorage := auth.NewMgoStorage()
	err := mgoStorage.OpenSession()
	if err != nil {
		log.Panic(err)
	}

	authProvider = auth.NewAuthProvider(mgoStorage)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			transformToken(req)
			req.URL.Scheme = "http"
			path := req.URL.Path
			sq, err := extractServiceName(path)
			if err != nil {
				return //TODO route on 404
			}
			servicePath, _ := registryClient.ServicesByName(sq.Service)
			req.URL.Path = sq.Query
			req.URL.Host = servicePath[0]
		},
	}

	//Handle login and register
	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/register", registerHandler)
	//else handle via proxy
	mux.Handle("/", proxy)
	http.ListenAndServe(":7070", mux)
}

type serviceAndQuery struct {
	Service string
	Query   string
}

func extractServiceName(path string) (serviceAndQuery, error) {
	sq := serviceAndQuery{}
	if len(path) > 2 {
		splittedPath := strings.Split(path[1:], "/")
		sq.Service = splittedPath[0]
		sq.Query = strings.Replace(path[1:], splittedPath[0], "", 1)
		return sq, nil
	}

	return sq, ErrNoServiceInUrl
}

func transformToken(req *http.Request) {
	refToken := req.Header.Get(TokenHeader)
	if len(refToken) == 0 {
		return
	}

	valToken, err := authProvider.ValueToken(refToken)

	if err == nil && len(valToken) != 0 {
		log.Printf("Setting valueToken %s", valToken)
		req.Header.Set(TokenHeader, valToken)
	}

}

func loginHandler(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	payload := struct {
		Email    string
		Password string
	}{}
	decodeErr := decoder.Decode(&payload)
	if decodeErr != nil {
		http.Error(rw, decodeErr.Error(), http.StatusBadRequest)
		return
	}

	token, err := authProvider.SignIn(payload.Email, payload.Password)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Header().Set(TokenHeader, token)
}

func registerHandler(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	user := auth.User{}
	decodeErr := decoder.Decode(&user)
	if decodeErr != nil {
		http.Error(rw, decodeErr.Error(), http.StatusBadRequest)
		return
	}
	signUpErr := authProvider.SignUp(user)
	if signUpErr != nil {
		http.Error(rw, signUpErr.Error(), http.StatusBadRequest)
		return
	}

	jsonVal, _ := json.Marshal(user)
	rw.Write(jsonVal)
}

// func logoutHandler(rw http.ResponseWriter, req *http.Request) {
// 	authProvider.SignOut(refToken)
// }
