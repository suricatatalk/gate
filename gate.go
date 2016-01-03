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
	"text/template"

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
	registryClient     *discovery.EtcdReigistryClient
	authProvider       auth.AuthProvider
	passManager        auth.PasswordManager
	actiavteUserRegex  = regexp.MustCompile(".*\\/activate\\/")
	passwordResetRegex = regexp.MustCompile(".*\\/resetpassword\\/")
	appCfg             *AppConfig
)

var (
	mailClient         client.MailClient
	activationComposer client.MessageComposer
	passResetComposer  client.MessageComposer
)

type AppConfig struct {
	Host   string `default:"127.0.0.1"`
	Port   string `default:"8080"`
	Name   string `default:"core1"`
	Domain string `default:"suricata.cleverapps.io"`
}

type MgoConfig struct {
	URI string `default:"127.0.0.1:27017"`
	DB  string `default:"surikata"`
}

type EtcdConfig struct {
	Endpoint string `default:"http://127.0.0.1:4001"`
}

type NatsConfig struct {
	Endpoint string `default:"nats://localhost:4222"`
}

// loadConfiguration loads the configuration of application
func loadConfiguration(app *AppConfig, mgo *MgoConfig, etcd *EtcdConfig, nats *NatsConfig) {
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
	err = envconfig.Process("nats", nats)
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
	natsCfg := &NatsConfig{}
	loadConfiguration(appCfg, mgoCfg, etcdCfg, natsCfg)

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

	initMail()
	var mailErr error
	mailClient, mailErr = client.NewNatsMailClient(natsCfg.Endpoint)
	if mailErr != nil {
		log.Errorf("Cannot initialize mail client: %s", mailErr.Error())
	}
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
	mgoAuthProvider := auth.NewAuthProvider(mgoStorage)
	authProvider = mgoAuthProvider
	passManager = mgoAuthProvider

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
	mux.HandleFunc("/activate/", activateHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/register", registerHandler)

	mux.HandleFunc("/requestpasswordreset", requestPasswordResetHandler)
	mux.HandleFunc("/resetpassword/", passwordResetHandler)
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

func initMail() {
	subjectTemp, _ := template.New("activate_subject").Parse("Suricata: Registration confirmation")
	messageTemp, _ := template.New("activate_message").Parse("Please confirm the registration on Suricata Talk website with click on this link {{.ConfirmationLink}}")
	activationComposer = &client.SuricataMessageComposer{
		subjectTemp,
		messageTemp,
	}

	subjectTemp, _ = template.New("passreset_subject").Parse("Suricata: Password reset")
	messageTemp, _ = template.New("passreset_message").Parse("Reset the password on following link {{.ResetLink}}")
	passResetComposer = &client.SuricataMessageComposer{
		subjectTemp,
		messageTemp,
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
	if err != nil && err != auth.ErrPasswordNotMatch {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	} else if err == auth.ErrPasswordNotMatch {
		http.Error(rw, err.Error(), http.StatusForbidden)
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

	actToken, err := authProvider.RequestUserActivationFor(user.Email)
	if err != nil {
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
	}
	sendActivationMailToUser(user.Email, actToken)

	jsonVal, _ := json.Marshal(user)
	rw.Write(jsonVal)
}

func activateHandler(rw http.ResponseWriter, req *http.Request) {
	log.Println("Activate handler")
	token := actiavteUserRegex.ReplaceAllString(req.URL.Path, "")
	if len(token) != 36 {
		http.Error(rw, ErrInavelidActivationToken.Error(), http.StatusBadRequest)
	}
	authProvider.ActivateUser(token)
}

func requestPasswordResetHandler(rw http.ResponseWriter, req *http.Request) {
	log.Println("Request password reset")
	email := req.FormValue("email")
	if len(email) == 0 {
		log.Infoln("Parameter \"email\" not found")
		http.Error(rw, "Parameter not found", http.StatusBadRequest)
		return
	}
	token, err := passManager.RequestPasswordResetFor(email)
	if err != nil {
		log.Error(err)
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}
	//TODO send mail with token
	err = sendPasswordResetMail(email, token)
	if err != nil {
		log.Error("Could not send password reset for mail: %s", email)
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func passwordResetHandler(rw http.ResponseWriter, req *http.Request) {
	tkn := passwordResetRegex.ReplaceAllString(req.URL.Path, "")
	pass := req.FormValue("password")
	err := passManager.ResetPasswordBy(tkn, pass)
	if err == auth.ErrResetTokenExpired {
		http.Error(rw, "Expired", http.StatusForbidden)

	} else if err != nil {
		log.Error(err)
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
	}
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

func sendActivationMailToUser(email, token string) error {
	messageStruct := struct{ ConfirmationLink string }{fmt.Sprintf("http://%s/activate/%s", appCfg.Domain, token)}
	subject := activationComposer.ComposeSubject(struct{}{})
	message := activationComposer.ComposeMessage(messageStruct)
	return mailClient.SendMail(email, subject, message)
}

func sendPasswordResetMail(email, token string) error {
	messageStruct := struct{ ResetLink string }{fmt.Sprintf("http://%s/resetpassword/%s", appCfg.Domain, token)}
	subject := passResetComposer.ComposeSubject(struct{}{})
	message := passResetComposer.ComposeMessage(messageStruct)
	return mailClient.SendMail(email, subject, message)
}
