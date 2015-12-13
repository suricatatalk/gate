package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/sebest/logrusly"
	"github.com/sohlich/etcd_discovery"
	"github.com/suricatatalk/gate/auth"
	"github.com/suricatatalk/mail/client"
	"github.com/yhat/wsutil"

	"github.com/kelseyhightower/envconfig"

	// "github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	// "github.com/markbates/goth/providers/twitter"
)

const (
	ServiceName = "gateway"
	TokenHeader = "X-AUTH"

	//Configuration keys
	KeyLogly = "LOGLY_TOKEN"
)

var (
	ErrNoServiceInUrl          = errors.New("No service definition in url")
	ErrInavelidActivationToken = errors.New("Invalid activation token")
	registryConfig             = discovery.EtcdRegistryConfig{
		ServiceName: ServiceName,
	}
	registryClient    *discovery.EtcdReigistryClient
	authProvider      auth.AuthProvider
	mailClient        client.MailClient
	actiavteUserRegex = regexp.MustCompile(".*\\/activate\\/")
	appCfg            *AppConfig
)

type AppConfig struct {
	Host   string `default:"127.0.0.1"`
	Port   string `default:"8080"`
	Name   string `default:"core1"`
	Domain string `default:"suricata.cleverapps.com"`
}

type MgoConfig struct {
	URI string `default:"127.0.0.1:27017"`
	DB  string `default:"surikata"`
}

type EtcdConfig struct {
	Endpoint string `default:"http://127.0.0.1:4001"`
}

// loadConfiguration loads the configuration of application
func loadConfiguration(app *AppConfig, mgo *MgoConfig, etcd *EtcdConfig) {
	err := envconfig.Process(ServiceName, app)
	if err != nil {
		log.Panicln(err)
	}
	err = envconfig.Process("mongodb", mgo)
	if err != nil {
		log.Panicln(err)
	}
	err = envconfig.Process("etcd", etcd)
	if err != nil {
		log.Panicln(err)
	}
	if len(os.Getenv(KeyLogly)) > 0 {
		log.Println("Loading logly token %s", os.Getenv(KeyLogly))
		hook := logrusly.NewLogglyHook(os.Getenv(KeyLogly),
			app.Host,
			log.InfoLevel,
			app.Name)
		log.AddHook(hook)
	}
}

func main() {
	//TODO os.Getenv("DOMAIN")
	configureSocial()
	// Load all configuration
	appCfg = &AppConfig{}
	mgoCfg := &MgoConfig{}
	etcdCfg := &EtcdConfig{}
	loadConfiguration(appCfg, mgoCfg, etcdCfg)

	// Service discovery config
	log.Infoln("Loading configuration for ETCD client")
	var registryErr error
	registryConfig.InstanceName = appCfg.Name
	registryConfig.BaseURL = fmt.Sprintf("%s:%s", appCfg.Host, appCfg.Port)
	registryConfig.EtcdEndpoints = []string{etcdCfg.Endpoint}
	registryClient, registryErr = discovery.New(registryConfig)
	if registryErr != nil {
		log.Panic(registryErr)
	}

	mailClient = client.NewSuricataMailClient(registryClient)

	//Mongo configuration
	log.Infoln("Loading configuration of MongoDB")
	mgoStorage := auth.NewMgoStorage()
	mgoStorage.ConnectionString = mgoCfg.URI
	mgoStorage.Database = mgoCfg.DB
	err := mgoStorage.OpenSession()
	if err != nil {
		log.Panic(err)
	}
	log.Infoln("Initializing auth provider")
	authProvider = auth.NewAuthProvider(mgoStorage)

	log.Infoln("Initializing reverse proxy")
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

	log.Infoln("Registering handlers")
	//Handle login and register
	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/activate", activateHandler)
	// mux.Get("/auth/{provider}/callback", handleSocialLogin)
	// mux.Get("/auth/{provider}", gothic.BeginAuthHandler)
	//else handle via proxy
	log.Infoln("Start listening on " + appCfg.Port)
	mux.Handle("/", multiProxy)
	serveErr := http.ListenAndServe(":"+appCfg.Port, mux)
	if serveErr != nil {
		log.Errorln(serveErr)
	}
}

func configureSocial() {

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
	log.Infof("Getting security token %s", refToken)
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
	user := auth.NewInactiveUser()
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

	sendMailToUser(user.Email, user.ActivationToken)

	user.ActivationToken = ""
	jsonVal, _ := json.Marshal(user)
	rw.Write(jsonVal)
}

func activateHandler(rw http.ResponseWriter, req *http.Request) {

	token := actiavteUserRegex.ReplaceAllString(req.URL.Path, "")
	if len(token) == 36 {
		http.Error(rw, ErrInavelidActivationToken.Error(), http.StatusBadRequest)
	}
	authProvider.ActivateUser(token)
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

func sendMailToUser(email, token string) error {
	messageStruct := struct{ ConfirmationLink string }{fmt.Sprintf("http://%s/activate/%s", appCfg.Domain, token)}
	return mailClient.SendMail(email, struct{}{}, messageStruct)
}
