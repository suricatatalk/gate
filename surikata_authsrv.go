package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/sohlich/etcd_registry"
	"github.com/sohlich/surikata_auth/auth"
)

var (
	registryConfig registry.EtcdRegistryConfig = registry.EtcdRegistryConfig{
		EtcdEndpoints: []string{"http://127.0.0.1:4001"},
		ServiceName:   "core",
		InstanceName:  "core1",
		BaseUrl:       "127.0.0.1:8080",
	}
	registryClient *registry.EtcdReigistryClient
)

func main() {
	var registryErr error
	registryClient, registryErr = registry.New(registryConfig)
	if registryErr != nil {
		log.Panic(registryErr)
	}
	mgoStorage := auth.NewMgoStorage()
	err := mgoStorage.OpenSession()
	if err != nil {
		log.Panic(err)
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			path := req.URL.Path
			log.Println(path)
			splittedPath := strings.Split(path[1:], "/")
			servicePath, _ := registryClient.ServicesByName(splittedPath[0])
			req.URL.Path = strings.Replace(path[1:], splittedPath[0], "", 1)
			req.URL.Host = servicePath[0]

			log.Println(req.URL)
		},
	}

	http.ListenAndServe(":7070", proxy)
}
