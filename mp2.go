package main

import (
	"net/http"
	"regexp"
	"gopkg.in/yaml.v2"
	"crypto/tls"
	"io/ioutil"
	"log"
	"os"
	"fmt"
)

var config map[string]interface{}
func main() {
	content, err := ioutil.ReadFile("config2.yaml")
	if err != nil {
		log.Fatalln("cannot read config")
	}
	yaml.Unmarshal(content, &config)

	var plainServer *http.Server
	var tlsServer *http.Server
	certdir := config["certdir"].(string)
	dir, err := os.Open(certdir)
	defer dir.Close()
	if err != nil {
		log.Fatal(certdir, err)
	}
	fi, err := dir.Readdir(0)
	if err != nil {
		log.Fatal("readdir", err)
	}
	mapCert := make(map[string]*tls.Certificate)
	defaultHost := config["default_host"]
	var default_certFile, default_keyFile string
	var default_cert tls.Certificate
	for _, subdir := range fi {
		log.Println("here")
		hostname := subdir.Name()
		certFile := certdir + "/" + hostname + "/fullchain.pem"
		keyFile := certdir + "/" + hostname + "/privkey.pem"
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		_ = err
		mapCert[hostname] = &cert
		if hostname == defaultHost {
			default_certFile = certFile
			default_keyFile = keyFile
			default_cert = cert
		}
	}
	_ = default_cert
	tlsConfig := &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) { return nil,nil},
		NameToCertificate: mapCert,
		//Certificates: []tls.Certificate{default_cert},
		Certificates: []tls.Certificate{},
	}
	tlsServer = &http.Server{
		Addr: ":443",
		TLSConfig: tlsConfig,
		Handler: http.NewServeMux(),
	}
	plainServer = &http.Server{
		Addr: ":80",
		Handler: http.NewServeMux(),
	}

	log.Println("here2")
	acmeHandler := http.FileServer(http.Dir(config["acmedir"].(string)))
	acmeHandler = http.FileServer(http.Dir("/dev/shm"))
	plainServer.Handler.(*http.ServeMux).HandleFunc("/", redirectHandler)
	plainServer.Handler.(*http.ServeMux).Handle("/.well-known", acmeHandler)
	tlsServer.Handler.(*http.ServeMux).HandleFunc("/", forwardHandler)
	go func() {
		log.Println("herex")
		//err := tlsServer.ListenAndServeTLS(default_certFile, default_keyFile)
		_ = default_certFile
		_ = default_keyFile
		err := tlsServer.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatal(err)
		}
	}()
	log.Println("here3")
	err = plainServer.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}


func redirectHandler(w http.ResponseWriter, req *http.Request) {
	var host string
	if (req.Host != "") {
		host = req.Host
	} else {
		host = req.URL.Host
	}
	portPattern, _ := regexp.Compile(":\\d+$")
	host = portPattern.ReplaceAllString(host, "")

	newURL, _ := req.URL.Parse("")
	newURL.Host = host
	newURL.Scheme = "https"

    http.Redirect(w, req, newURL.String(), http.StatusMovedPermanently)
}

func forwardHandler(w http.ResponseWriter, req *http.Request) {
	var host string
	if (req.Host != "") {
		host = req.Host
	} else {
		host = req.URL.Host
	}
	portPattern, _ := regexp.Compile(":\\d+$")
	host = portPattern.ReplaceAllString(host, "")

	port, ok := config["forwardtable"].(map[interface{}]interface{})["https"].(map[interface{}]interface{})[host].(int)
	if !ok {
		port = config["forwardtable"].(map[interface{}]interface{})["https"].(map[interface{}]interface{})["default"].(int)
	}

	host = fmt.Sprintf("localhost:%d", port)
	newURL, _ := req.URL.Parse("")
	newURL.Scheme = "https"
	newURL.Host = host

	req.Host = host
	req.URL = newURL
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Write(w)
}
