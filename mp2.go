package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
)

var config map[string]interface{}
var LOG_FILE = "mp2.log"
var portPattern = regexp.MustCompile(":\\d+$")

func main() {
	fh, err := os.OpenFile(LOG_FILE, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalln(err, "cannot open logfile")
	}
	log.SetOutput(fh)
	content, err := ioutil.ReadFile("config2.yaml")
	if err != nil {
		log.Fatalln(err, "cannot read config")
	}
	yaml.Unmarshal(content, &config)

	var plainServer *http.Server
	var tlsServer *http.Server
	certdir := config["certdir"].(string)
	dir, err := os.Open(certdir)
	defer dir.Close()
	if err != nil {
		log.Fatal("cannot open certdir", certdir, err)
	}
	fi, err := dir.Readdir(0)
	if err != nil {
		log.Fatal("cannot readdir", err)
	}
	mapCert := make(map[string]*tls.Certificate)
	defaultHost := config["default_host"]
	var default_certFile, default_keyFile string
	var default_cert tls.Certificate
	for _, subdir := range fi {
		//log.Println("here")
		hostname := subdir.Name()
		certFile := certdir + "/" + hostname + "/fullchain.pem"
		keyFile := certdir + "/" + hostname + "/privkey.pem"
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatal(err, "load cert failed", certFile)
		}
		mapCert[hostname] = &cert
		if hostname == defaultHost {
			default_certFile = certFile
			default_keyFile = keyFile
			default_cert = cert
		}
	}
	_ = default_cert
	tlsConfig := &tls.Config{
		//GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) { return nil,nil},
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
		//Certificates: []tls.Certificate{default_cert},
		//Certificates: []tls.Certificate{},
		Certificates: nil,
	}
	tlsServer = &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
		Handler:   http.NewServeMux(),
	}
	plainServer = &http.Server{
		Addr:    ":80",
		Handler: http.NewServeMux(),
	}

	//log.Println("here2")
	//acmeHandler := http.FileServer(http.Dir(config["acmedir"].(string)))

	//acmeHandler = http.FileServer(http.Dir("/dev/shm"))
	plainServer.Handler.(*http.ServeMux).HandleFunc("/", redirectHandler)
	//plainServer.Handler.(*http.ServeMux).Handle("/.well-known/", acmeHandler)
	plainServer.Handler.(*http.ServeMux).HandleFunc("/.well-known/", acmeHandler)
	tlsServer.Handler.(*http.ServeMux).HandleFunc("/", forwardHandler)
	go func() {
		//log.Println("herex")
		//err := tlsServer.ListenAndServeTLS(default_certFile, default_keyFile)
		_ = default_certFile
		_ = default_keyFile
		err := tlsServer.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatal("tlsServer", err)
		}
	}()
	//log.Println("here3")
	err = plainServer.ListenAndServe()
	if err != nil {
		log.Fatal("plainServer", err)
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

	port, ok := config["forwardtable"].(map[interface{}]interface{})["https"].(map[interface{}]interface{})[host].(int)
	if !ok {
		port = config["forwardtable"].(map[interface{}]interface{})["https"].(map[interface{}]interface{})["default"].(int)
	}

	host = fmt.Sprintf("%s:%d", host, port)
	newURL, _ := req.URL.Parse("")
	newURL.Scheme = "https"
	newURL.Host = host

	req.Host = host
	req.URL = newURL
	client := &http.Client{}
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
		log.Println("client.Do err", err)
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
	//resp.Write(w)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println("io.Copy err", err)
	}
	resp.Body.Close()
}
