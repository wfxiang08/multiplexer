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
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"
	"github.com/gorilla/websocket"
	"sync"
)

var configFile = flag.String("config", "config2.yaml", "path to config file, defailt config2.yaml")

var config map[string]interface{}
var LOG_FILE = "mp2.log"
var portPattern = regexp.MustCompile(":\\d+$")

//var httpClient = &http.Client{}
// for local test
var httpClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		Proxy: nil,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		DialTLS:               nil,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	},
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// FIXME strip port and check
		log.Println("Origin:", r.Header.Get("Origin"))
		log.Println("Host:", r.Host)
		return true
	},
}

// share tls config with httpClient
var websocketDialer = &websocket.Dialer{
	Proxy: nil,
	TLSClientConfig: httpClient.Transport.(*http.Transport).TLSClientConfig,
}

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

	if _, ok := config["skip_verify"]; ok && config["skip_verify"] != 0 {
		httpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
		//fmt.Println("%#v\n%#v\n", httpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify, websocketDialer.TLSClientConfig.InsecureSkipVerify)
	}

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
		Certificates:      nil,
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

var acmeFilter = regexp.MustCompile("^/\\.well-known")

func acmeHandler(w http.ResponseWriter, req *http.Request) {
	logRequest(req)
	if !acmeFilter.MatchString(req.URL.Path) {
		log.Println("bad req url path", req.URL.Path)
		return
	}
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

	pair, ok := config["forwardtable"].(map[interface{}]interface{})[host]
	if !ok {
		pair = config["forwardtable"].(map[interface{}]interface{})["default"]
	}

	pair_map := pair.(map[interface{}]interface{})
	port := pair_map["port"].(int)

	host_interface, ok := pair_map["host"]
	if ok {
		host = host_interface.(string)
	}

	hostport := fmt.Sprintf("%s:%d", host, port)

	newURL, _ := req.URL.Parse("")
	newURL.Scheme = "https"
	newURL.Host = hostport

	req.Host = hostport
	req.URL = newURL
	//client := &http.Client{}
	// reuse
	client := httpClient
	// unset it
	req.RequestURI = ""

	// FIXME: all hop-by-hop headers
	req.Header.Del("Accept-Encoding")
	req.Header.Del("Proxy-Connection")
	// unset Connection
	// drop "Connection"
	// FIXME case sensitive?
	if req.Header.Get("Connection") != "Upgrade" {
		req.Header.Del("Connection")
	} else if req.Header.Get("Upgrade") == "websocket" {
		websocketHandler(w, req, newURL)
		return
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


func websocketHandler(w http.ResponseWriter, req *http.Request, newURL *url.URL) {
	// force websocket-tls
	newURL.Scheme = "wss"
	log.Println("websocket upstream at", newURL.String())

	// downstream
	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		log.Println("upgrade", err)
		return
	}
	defer conn.Close()

	req.Header.Del("Upgrade")
	req.Header.Del("Connection")
	req.Header.Del("Sec-WebSocket-Key")
	req.Header.Del("Sec-WebSocket-Version")
	req.Header.Del("Sec-WebSocket-Protocol")
	// upstream
	connUp, respUp, err := websocketDialer.Dial(newURL.String(), req.Header)
	if err != nil {
		log.Println("dial websocket:", err)
		if err == websocket.ErrBadHandshake {
			for key, value := range respUp.Header {
				// filter headers
				if key == "Connection" {
					continue
				}
				w.Header()[key] = value
			}
			w.WriteHeader(respUp.StatusCode)
			_, err = io.Copy(w, respUp.Body)
			if err != nil {
				log.Println("io.Copy err:", err)
			}
			respUp.Body.Close()
		}
		return
	}
	defer connUp.Close()


	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer log.Println("down->up done")
		for {
			messageType, p, err := conn.ReadMessage()
			if err != nil {
				log.Println("t01", err)
				connUp.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Time{})
				return
			}
			log.Println("down->up", string(p))
			err = connUp.WriteMessage(messageType, p)
			if err != nil {
				log.Println("t02", err)
				// FIXME
				conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Time{})
				return
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer log.Println("up->down done")
		for {
			messageType, p, err := connUp.ReadMessage()
			if err != nil {
				log.Println("t03", err)
				conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Time{})
				return
			}
			log.Println("up->down", string(p))
			err = conn.WriteMessage(messageType, p)
			if err != nil {
				log.Println("t04", err)
				// FIXME
				connUp.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Time{})
				return
			}
		}
	}()
	wg.Wait()
	log.Println("waitgroup finished")
}
