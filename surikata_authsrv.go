package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/sohlich/etcd_discovery"
	"github.com/sohlich/surikata_auth/auth"
	"github.com/yhat/wsutil"

	//"github.com/gorilla/pat"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/twitter"
)

const (
	ServiceName = "gateway"
	TokenHeader = "X-AUTH"

	//Configuration keys
	KeyGatewayHost  = "GATEWAY_HOST"
	KeyGatewayPort  = "GATEWAY_PORT"
	KeyGatewayName  = "GATEWAY_NAME"
	KeyMongoURI     = "MONGODB_URI"
	KeyMongoDB      = "MONGODB_DB"
	KeyETCDEndpoint = "ETCD_ENDPOINT"
)

var (
	ErrNoServiceInUrl                              = errors.New("No service definition in url")
	registryConfig    discovery.EtcdRegistryConfig = discovery.EtcdRegistryConfig{
		ServiceName: ServiceName,
	}
	registryClient *discovery.EtcdReigistryClient
	authProvider   auth.AuthProvider
)

func main() {
	//TODO os.Getenv("DOMAIN")
	goth.UseProviders(
		twitter.NewAuthenticate("e8O58aGBxlI3ccS6g5mYQ", "1EA77vKfzGh37WqVj7Duoxdm5DgdeDyc9kzm4Y7XRg", " http://6d8798e2.ngrok.io/auth/twitter/callback"),
	)

	// Service discovery config
	log.Infoln("Loading configuration for ETCD client")
	var registryErr error
	registryConfig.InstanceName = os.Getenv(KeyGatewayName)
	registryConfig.BaseURL = fmt.Sprintf("%s:%s", os.Getenv(KeyGatewayHost), os.Getenv(KeyGatewayPort))
	registryConfig.EtcdEndpoints = []string{os.Getenv(KeyETCDEndpoint)}
	registryClient, registryErr = discovery.New(registryConfig)
	if registryErr != nil {
		log.Panic(registryErr)
	}

	//Mongo configuration
	mgoStorage := auth.NewMgoStorage()
	mgoStorage.ConnectionString = os.Getenv(KeyMongoURI)
	mgoStorage.Database = os.Getenv(KeyMongoDB)
	err := mgoStorage.OpenSession()
	if err != nil {
		log.Panic(err)
	}

	authProvider = auth.NewAuthProvider(mgoStorage)

	wsproxy := &wsutil.ReverseProxy{
		Director: schemeDirector("ws://"),
	}

	proxy := &httputil.ReverseProxy{
		Director: schemeDirector("http"),
	}

	multiProxy := &MultiProxy{
		wsproxy,
		proxy,
	}

	//Handle login and register
	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/register", registerHandler)
	// mux.Get("/auth/{provider}/callback", handleSocialLogin)
	// mux.Get("/auth/{provider}", gothic.BeginAuthHandler)
	//else handle via proxy
	mux.Handle("/", multiProxy)
	http.ListenAndServe(":"+os.Getenv(KeyGatewayPort), mux)
}

type MultiProxy struct {
	ws   *wsutil.ReverseProxy
	http *httputil.ReverseProxy
}

func (m *MultiProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if wsutil.IsWebSocketRequest(r) {
		m.ws.ServeHTTP(rw, r)
	} else {
		m.http.ServeHTTP(rw, r)
	}

}

func schemeDirector(scheme string) func(req *http.Request) {
	return func(req *http.Request) {
		log.Infof("Getting request headers {}", req.Header)
		transformToken(req)
		req.URL.Scheme = scheme
		path := req.URL.Path
		sq, err := extractServiceName(path)
		if err != nil {
			return //TODO route on 404
		}
		servicePath, _ := registryClient.ServicesByName(sq.Service)
		req.URL.Path = sq.Query
		if len(servicePath) < 1 {
			log.Errorf("No service by name %s found", sq.Service)
			return
		}
		req.URL.Host = servicePath[0]
		log.Printf("Output URL {}", req.URL)
	}
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
		log.Infof("Setting valueToken %s", valToken)
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

func handleSocialLogin(rw http.ResponseWriter, req *http.Request) {
	log.Println(gothic.GetState(req))
	socialUser, err := gothic.CompleteUserAuth(rw, req)
	if err != nil {
		log.Println(err)
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	user := auth.User{}
	user.UserID = socialUser.UserID
	user.Email = socialUser.Email

	log.Println(socialUser.UserID)
	log.Println(socialUser.AccessToken)
	log.Println(socialUser.NickName)
}
