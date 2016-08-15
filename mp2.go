// only suport client with SNI
package main

import (
	"crypto/tls"
	"encoding/hex"
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

var config2 Config

type ForwardTableEntry struct {
	Port int `yaml:"port"`
	Host string `yaml:"host"`
}

type Config struct {
	ForwardTable map[string]ForwardTableEntry `yaml:"forwardtable"`
	PlainPort int `yaml:"plain_port"`
	TlsPort int `yaml:"tls_port"`
	ListenAddr string `yaml:"listen"`
	AcmeDir string `yaml:"acmedir"`
	CertDir string `yaml:"certdir"`
	LogFile string `yaml:"log_file"`
	SkipVerify int `yaml:"skip_verify"`
	LogDebug int `yaml:"log_debug"`
}



// logrotate?
var LOG_FILE = "mp2.log"
// FIXME use net.SplitHostPort
var portPattern = regexp.MustCompile(":\\d+$")
var logDebug = false

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
		log.Println("[DEBUG] Origin:", r.Header.Get("Origin"))
		log.Println("[DEBUG] Host:", r.Host)
		return true
	},
}

// FIXME share tls config with httpClient?
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

	// try yaml tags
	err = yaml.Unmarshal(content, &config2)
	if err != nil {
		log.Fatalln("yaml unmarshal", err)
	}
	log.Println(config2)
	log.Printf("%#v\n", config2)

	if config2.LogFile != "" {
		LOG_FILE = config2.LogFile
	}

	fh, err := os.OpenFile(LOG_FILE, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalln("cannot open logfile:", err)
	}
	log.SetOutput(fh)

	if config2.SkipVerify != 0 {
		httpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
		//fmt.Println("%#v\n%#v\n", httpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify, websocketDialer.TLSClientConfig.InsecureSkipVerify)
	}

	if config2.LogDebug != 0 {
		logDebug = true
	}

	log.Println(config2.ForwardTable)

	var plainServer *http.Server
	var tlsServer *http.Server
	certdir := config2.CertDir
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
		Addr:      fmt.Sprintf("%s:%d", config2.ListenAddr, config2.TlsPort),
		TLSConfig: tlsConfig,
		Handler:   http.NewServeMux(),
	}
	plainServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config2.ListenAddr, config2.PlainPort),
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
	filename := config2.AcmeDir + "/" + req.URL.Path
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

	upstream, ok := config2.ForwardTable[host]
	if !ok {
		upstream = config2.ForwardTable["default"]
	}

	port := upstream.Port

	if upstream.Host != "" {
		host = upstream.Host
	}

	hostport := fmt.Sprintf("%s:%d", host, port)

	newURL, _ := req.URL.Parse("")
	newURL.Scheme = "https"
	newURL.Host = hostport

	// save previous Host in Header
	//req.Header.Set("Host", req.Host)
	// the outside host
	req.Host = host

	// the transport host
	req.URL = newURL
	//client := &http.Client{}
	// reuse
	client := httpClient
	// unset it
	req.RequestURI = ""

	// FIXME: should copy in_req to out_req

	// FIXME: all hop-by-hop headers
	// RFC2616, 13.5.1
	//Connection
	req.Header.Del("Keep-Alive")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("TE")
	req.Header.Del("Trailer") // not Trailers RFC2616 errata...
	req.Header.Del("Transfer-Encoding")
	//Upgrade

	// non-standard
	req.Header.Del("Accept-Encoding")
	req.Header.Del("Proxy-Connection")

	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Real-IP")
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		req.Header.Set("X-Forwarded-For", clientIP)
		req.Header.Set("X-Real-IP", clientIP)
	} else {
		log.Println("net.SplitHostPort", req.RemoteAddr, err)
	}

	req.Header.Del("X-Forwarded-Proto")
	req.Header.Set("X-Forwarded-Proto", "https")

	// unset Connection
	// drop "Connection"
	// FIXME case sensitive?
	if req.Header.Get("Connection") != "Upgrade" {
		req.Header.Del("Connection")
		req.Header.Del("Upgrade")
	} else if req.Header.Get("Upgrade") == "websocket" {
		websocketHandler(w, req, newURL)
		return
	}

	//req.Header.Del("Connection")
	//req.Header.Del("Upgrade")

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
	if len(resp.Trailer) > 0 {
		// FIXME
		log.Println("response has trailer?")
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
	log.Println("[DEBUG] websocket upstream at", newURL.String())

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
	go websocketTunnel("[DEBUG] down->up", wg, conn, connUp)
	wg.Add(1)
	go websocketTunnel("[DEBUG] up->down", wg, connUp, conn)
	wg.Wait()
	log.Println("[DEBUG] waitgroup finished")
}

func websocketTunnel(logTag string, wg sync.WaitGroup, connFrom, connTo *websocket.Conn) {
	defer wg.Done()
	defer debugLog(logTag, "done")
	for {
		messageType, p, err := connFrom.ReadMessage()
		if err != nil {
			debugLog(logTag, "t01", err)
			connTo.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Time{})
			return
		}
		if messageType == websocket.TextMessage {
			debugLog(logTag, messageType, string(p))
		} else {
			debugLog(logTag, messageType, hex.Dump(p))
		}
		err = connTo.WriteMessage(messageType, p)
		if err != nil {
			debugLog(logTag, "t02", err)
			// FIXME
			connFrom.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Time{})
			return
		}
	}
}

func debugLog(v ...interface{}) {
	if logDebug {
		log.Println(v...)
	}
}
