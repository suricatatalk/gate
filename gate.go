package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"

	"golang.org/x/net/http2"

	log "github.com/Sirupsen/logrus"
	"github.com/nats-io/nats"
	"github.com/sebest/logrusly"
	"github.com/sohlich/nats-proxy"
	"github.com/suricatatalk/gate/jwt"
	"github.com/suricatatalk/gate/storage"
	"github.com/suricatatalk/guardian/auth"
	"github.com/suricatatalk/mail/client"

	"github.com/kelseyhightower/envconfig"
	// "github.com/markbates/goth"
	// "github.com/markbates/goth/providers/twitter"
)

const (
	ServiceName = "gateway"
	TokenHeader = "X-Auth"

	//Configuration keys
	KeyLogly = "LOGLY_TOKEN"
)

var (
	ErrNoServiceInUrl          = errors.New("No service definition in url")
	ErrInavelidActivationToken = errors.New("Invalid activation token")
	actiavteUserRegex          = regexp.MustCompile(".*\\/activate\\/")
	passwordResetRegex         = regexp.MustCompile(".*\\/resetpassword\\/")
	appCfg                     *AppConfig
	tokenStorage               storage.DataStorage
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

type RedisConfig struct {
	URI      string `default:"127.0.0.1:6379"`
	Password string `default:""`
	DB       int64  `default:"0"`
}

type NatsConfig struct {
	Endpoint string `default:"nats://localhost:4222"`
}

// loadConfiguration loads the configuration of application
func loadConfiguration(app *AppConfig, rdis *RedisConfig, nats *NatsConfig) {
	err := envconfig.Process(ServiceName, app)
	if err != nil {
		log.Panicln(err)
	}
	err = envconfig.Process("redis", rdis)
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
	rdisCfg := &RedisConfig{}
	natsCfg := &NatsConfig{}
	loadConfiguration(appCfg, rdisCfg, natsCfg)

	// Service discovery config

	//Mongo configuration
	log.Infoln("Loading configuration of Redis")
	rdisStorage := storage.NewRedisStorage()
	rdisStorage.URL = rdisCfg.URI
	rdisStorage.Password = rdisCfg.Password
	rdisStorage.Database = rdisCfg.DB
	tokenStorage = rdisStorage
	err := tokenStorage.OpenSession()
	defer tokenStorage.CloseSession()
	if err != nil {
		log.Panic(err)
	}

	log.Infoln("Initializing NATS proxy")
	proxyConn, _ := nats.Connect(natsCfg.Endpoint)
	multiProxy, err := natsproxy.NewNatsProxy(proxyConn)
	multiProxy.AddHook("/login.*", loginHook)
	defer proxyConn.Close()
	if err != nil {
		log.Panic("Cannot initialize NATS proxy")
	}

	log.Infoln("Registering handlers")
	//Handle login and register
	mux := http.NewServeMux()
	log.Infoln("Start listening on " + appCfg.Port)
	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		log.Println("Handling")
		transformToken(req)
		log.Println(req.Header)
		multiProxy.ServeHTTP(rw, req)
	})

	//Init HTTP2 server
	srv := &http.Server{
		Addr:    ":" + appCfg.Port,
		Handler: mux,
	}
	http2.ConfigureServer(srv, nil)
	serveErr := srv.ListenAndServe()
	if serveErr != nil {
		log.Errorln(serveErr)
	}
}

func loginHook(resp *natsproxy.Response) {

	userJSON := resp.Header.Get(TokenHeader)
	user := auth.User{}
	json.Unmarshal([]byte(userJSON), &user)
	jwtToken, err := jwt.GenerateJwtToken(user)
	if err != nil {
		log.Error(err)
	}
	var token storage.Token
	if token, err = storage.NewToken(user, jwtToken); err != nil {
		log.Error(err)
		return
	}

	err = tokenStorage.InsertToken(token)
	if err != nil {
		log.Error(err)
		resp.StatusCode = http.StatusInternalServerError
		resp.Header.Del(TokenHeader)
		return
	}
	resp.Header.Set(TokenHeader, token.RefToken)
}

func configureSocial() {
	//No Op
}

func transformToken(req *http.Request) {
	refToken := req.Header.Get(TokenHeader)
	if len(refToken) == 0 {
		return
	}
	log.Infof("Getting security token %s", refToken)
	valToken, err := tokenStorage.TokenByRefToken(refToken)

	if err == nil && len(valToken.JwtToken) != 0 {
		log.Infof("Setting valueToken %s", valToken)
		req.Header.Set(TokenHeader, valToken.JwtToken)
	}
}

// func handleSocialLogin(rw http.ResponseWriter, req *http.Request) {
// 	log.Println(gothic.GetState(req))
// 	socialUser, err := gothic.CompleteUserAuth(rw, req)
// 	if err != nil {
// 		log.Println(err)
// 		http.Error(rw, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	user := auth.User{}
// 	user.UserID = socialUser.UserID
// 	user.Email = socialUser.Email

// 	log.Println(socialUser.UserID)
// 	log.Println(socialUser.AccessToken)
// 	log.Println(socialUser.NickName)
// }
