// only suport client with SNI
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
)

var configFile = flag.String("config", "config2.yaml", "path to config file, defailt config2.yaml")

var config map[string]interface{}
var LOG_FILE = "mp2.log"
var portPattern = regexp.MustCompile(":\\d+$")

var httpClient = &http.Client{}

func main() {
	flag.Parse()

	content, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalln("cannot read config:", err)
	}
	yaml.Unmarshal(content, &config)

	if _, ok := config["logfile"]; ok {
		LOG_FILE = config["logfile"].(string)
	}

	fh, err := os.OpenFile(LOG_FILE, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalln("cannot open logfile:", err)
	}
	log.SetOutput(fh)

	log.Println(config["forwardtable"])

	var plainServer *http.Server
	var tlsServer *http.Server
	certdir := config["certdir"].(string)
	dir, err := os.Open(certdir)
	defer dir.Close()
	if err != nil {
		log.Fatal("cannot open certdir:", certdir, err)
	}
	fi, err := dir.Readdir(0)
	if err != nil {
		log.Fatal("cannot readdir:", err)
	}
	mapCert := make(map[string]*tls.Certificate)
	plainPort := config["plain_port"]
	tlsPort := config["tls_port"]
	listenAddr := config["listen"]
	for _, subdir := range fi {
		hostname := subdir.Name()
		certFile := certdir + "/" + hostname + "/fullchain.pem"
		keyFile := certdir + "/" + hostname + "/privkey.pem"
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatal("load cert failed", certFile, err)
		}
		mapCert[hostname] = &cert
	}
	tlsConfig := &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sn := clientHello.ServerName
			if sn != "" {
				cert, ok := mapCert[sn]
				if ok {
					return cert, nil
				}
			}
			return nil, errors.New("<" + sn + "> not found")
		},
		NameToCertificate: mapCert,
		Certificates: nil,
	}
	tlsServer = &http.Server{
		Addr:      fmt.Sprintf("%s:%d", listenAddr, tlsPort),
		TLSConfig: tlsConfig,
		Handler:   http.NewServeMux(),
	}
	plainServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", listenAddr, plainPort),
		Handler: http.NewServeMux(),
	}

	plainServer.Handler.(*http.ServeMux).HandleFunc("/", redirectHandler)
	plainServer.Handler.(*http.ServeMux).HandleFunc("/.well-known/", acmeHandler)
	tlsServer.Handler.(*http.ServeMux).HandleFunc("/", forwardHandler)
	go func() {
		err := tlsServer.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatalln("tlsServer error:", err)
		}
	}()
	err = plainServer.ListenAndServe()
	if err != nil {
		log.Fatalln("plainServer error:", err)
	}
}

func logRequest(req *http.Request) {
	log.Printf("%T <%s> \"%v\" %s <%s> %v %v %s %v\n", req, req.RemoteAddr, req.URL, req.Proto, req.Host, req.Header, req.Form, req.RequestURI, req.TLS)
}

func acmeHandler(w http.ResponseWriter, req *http.Request) {
	logRequest(req)
	filename := config["acmedir"].(string) + "/" + req.URL.Path
	log.Println("servefile", filename)
	http.ServeFile(w, req, filename)
}

func redirectHandler(w http.ResponseWriter, req *http.Request) {
	logRequest(req)
	var host string
	if req.Host != "" {
		host = req.Host
	} else {
		host = req.URL.Host
	}
	host = portPattern.ReplaceAllString(host, "")

	newURL, _ := req.URL.Parse("")
	newURL.Host = host
	newURL.Scheme = "https"

	http.Redirect(w, req, newURL.String(), http.StatusMovedPermanently)
}

func forwardHandler(w http.ResponseWriter, req *http.Request) {
	logRequest(req)
	var host string
	if req.Host != "" {
		host = req.Host
	} else {
		host = req.URL.Host
	}
	host = portPattern.ReplaceAllString(host, "")

	port, ok := config["forwardtable"].(map[interface{}]interface{})[host].(int)
	if !ok {
		port = config["forwardtable"].(map[interface{}]interface{})["default"].(int)
	}

	host = fmt.Sprintf("%s:%d", host, port)
	newURL, _ := req.URL.Parse("")
	newURL.Scheme = "https"
	newURL.Host = host

	req.Host = host
	req.URL = newURL
	//client := &http.Client{}
	// reuse
	client := httpClient
	// unset it
	req.RequestURI = ""
	// unset Connection
	_, ok = req.Header["Connection"]
	// drop "Connection"
	if ok {
		delete(req.Header, "Connection")
	}
	resp, err := client.Do(req)
	//log.Println(resp)
	if err != nil {
		log.Println("client.Do err:", err)
		return
	}
	for key, value := range resp.Header {
		// filter headers
		if key == "Connection" {
			continue
		}
		w.Header()[key] = value
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println("io.Copy err:", err)
	}
	resp.Body.Close()
}
