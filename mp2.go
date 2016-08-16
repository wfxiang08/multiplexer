// only suport client with SNI
package main

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var configFile = flag.String("config", "config2.yaml", "path to config file, default config2.yaml")

var config Config

type Target struct {
	Port string `yaml:"port"`
	Host string `yaml:"host"`
}

type Config struct {
	ForwardTable map[string]Target `yaml:"forwardtable"`
	PlainPort    string            `yaml:"plain_port"`
	TlsPort      string            `yaml:"tls_port"`
	ListenAddr   string            `yaml:"listen"`
	AcmeDir      string            `yaml:"acmedir"`
	CertDir      string            `yaml:"certdir"`
	LogFile      string            `yaml:"log_file"`
	SkipVerify   int               `yaml:"skip_verify"`
	LogDebug     int               `yaml:"log_debug"`
}

// logrotate?
var LOG_FILE = "mp2.log"

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
		// FIXME strip port and check origin == host?
		debugLog("[DEBUG] Origin:", r.Header.Get("Origin"))
		debugLog("[DEBUG] Host:", r.Host)
		return true
	},
}

// FIXME share tls config with httpClient?
var websocketDialer = &websocket.Dialer{
	Proxy:           nil,
	TLSClientConfig: httpClient.Transport.(*http.Transport).TLSClientConfig,
}

// Parse config file, set up log file, load cert/key pairs, set up
// plain/tls servers
func main() {
	// config
	flag.Parse()
	content, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalln("cannot read config:", err)
	}
	err = yaml.Unmarshal(content, &config)
	if err != nil {
		log.Fatalln("yaml unmarshal", err)
	}
	log.Printf("%#v\n", config)

	// logfile
	if config.LogFile != "" {
		LOG_FILE = config.LogFile
	}
	fh, err := os.OpenFile(LOG_FILE, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalln("cannot open logfile:", err)
	}
	log.SetOutput(fh)
	//defer fh.Close()?
	log.Printf("Current config: %#v\n", config)

	if config.SkipVerify != 0 {
		httpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
		//fmt.Println("%#v\n%#v\n", httpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify, websocketDialer.TLSClientConfig.InsecureSkipVerify)
	}

	var plainServer *http.Server
	var tlsServer *http.Server
	fi, err := ioutil.ReadDir(config.CertDir)
	if err != nil {
		log.Fatal("cannot readdir:", config.CertDir, err)
	}
	mapCert := make(map[string]*tls.Certificate)
	for _, subdir := range fi {
		hostname := subdir.Name()
		certFile := config.CertDir + "/" + hostname + "/fullchain.pem"
		keyFile := config.CertDir + "/" + hostname + "/privkey.pem"
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatal("load cert failed", certFile, err)
		}
		mapCert[hostname] = &cert
	}
	tlsConfig := &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName != "" {
				cert, ok := mapCert[clientHello.ServerName]
				if ok {
					return cert, nil
				}
			}
			return nil, errors.New("<" + clientHello.ServerName + "> not found")
		},
		NameToCertificate: mapCert,
		Certificates:      nil,
	}
	tlsServer = &http.Server{
		Addr:      net.JoinHostPort(config.ListenAddr, config.TlsPort),
		TLSConfig: tlsConfig,
		Handler:   http.NewServeMux(),
	}
	plainServer = &http.Server{
		Addr:    net.JoinHostPort(config.ListenAddr, config.PlainPort),
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

// Log request and Header (probabily should log less)
func logRequest(req *http.Request) {
	log.Printf("%T <%s> \"%v\" %s <%s> %v %v %s %v\n", req, req.RemoteAddr, req.URL, req.Proto, req.Host, req.Header, req.Form, req.RequestURI, req.TLS)
}

var acmeFilter = regexp.MustCompile("^/\\.well-known")
// Handle acme (letsencrypt) SimpleHttp/http-01 challenge
// (or other /.well-known urls)
func acmeHandler(w http.ResponseWriter, req *http.Request) {
	logRequest(req)
	if !acmeFilter.MatchString(req.URL.Path) {
		log.Println("bad req url path", req.URL.Path)
		return
	}
	filename := config.AcmeDir + "/" + req.URL.Path
	log.Println("servefile", filename)
	http.ServeFile(w, req, filename)
}

// Strip ":port" from req.Host if present
func parseHost(req *http.Request) string {
	//if req.Host == "" {
	//	log.Fatalln("req.Host empty") // net/http server set req.Host automatically
	//}
	host_strip, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		//log.Println("net.SplitHostPort error", err)
		return req.Host
	}
	return host_strip
}

// For http, send redirection to https
func redirectHandler(w http.ResponseWriter, req *http.Request) {
	logRequest(req)
	host := parseHost(req)
	// [?] port, err := net.LookupPort("tcp", "https") and strconv.Itoa()
	if config.TlsPort != "443" {
		host = net.JoinHostPort(host, config.TlsPort)
	}
	newURL, _ := req.URL.Parse("")
	newURL.Host = host
	newURL.Scheme = "https"
	http.Redirect(w, req, newURL.String(), http.StatusMovedPermanently)
}

// For https, forward requests to upstream https (application) servers
func forwardHandler(w http.ResponseWriter, req *http.Request) {
	logRequest(req)
	debugLog("host:", req.Host)
	debugLog("origin:", req.Header.Get("Origin"))
	host := parseHost(req)

	// use case-insensitive comparison for host name
	upstream, ok := config.ForwardTable[strings.ToLower(host)]
	if !ok {
		upstream = config.ForwardTable["default"]
	}
	port := upstream.Port
	if upstream.Host != "" {
		host = upstream.Host
	}

	hostport := net.JoinHostPort(host, port)
	newURL, _ := req.URL.Parse("")
	newURL.Scheme = "https"
	newURL.Host = hostport

	// the outside host: use the original value from req
	// (keep ":port" unstripped, useful if TlsPort is not 443)
	//req.Host = host
	// the transport host
	req.URL = newURL
	// unset it
	req.RequestURI = ""

	// FIXME: should copy in_req to out_req
	// All hop-by-hop headers, RFC2616, 13.5.1
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

	// reverse proxy
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Real-IP")
	// RemoteAddr contains "IP:port"
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		req.Header.Set("X-Forwarded-For", clientIP)
		req.Header.Set("X-Real-IP", clientIP)
	} else {
		log.Println("net.SplitHostPort", req.RemoteAddr, err)
	}
	req.Header.Del("X-Forwarded-Proto")
	req.Header.Set("X-Forwarded-Proto", "https")

	connectionList := parseHeader(req.Header, "Connection")
	log.Println(connectionList)

	if websocket.IsWebSocketUpgrade(req) {
		websocketHandler(w, req, newURL)
		return
	} else {
		req.Header.Del("Connection")
		req.Header.Del("Upgrade")
		for _, key := range connectionList {
			req.Header.Del(key)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Println("client.Do err:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// copy and filter headers
	for key, value := range resp.Header {
		if key == "Connection" {
			continue
		}
		w.Header()[key] = value
	}
	// FIXME process trailers?
	if len(resp.Trailer) > 0 {
		log.Println("response has trailer?")
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println("io.Copy err:", err)
	}
	resp.Body.Close()
}

// Combine header lines, and split at "," (only useful for certain headers)
func parseHeader (header http.Header, key string) []string {
	var tokenList []string
	key_canon := http.CanonicalHeaderKey(key)
	if _, ok := header[key_canon]; !ok {
		return tokenList // empty (nil)
	}
	for _, line := range header[key_canon] {
		lineList := strings.Split(line, ",")
		for _, v := range lineList {
			v = strings.TrimSpace(v)
			v = strings.ToLower(v)
			tokenList = append(tokenList, v)
		}
	}
	return tokenList
}

// Handle upgrades to websocket
func websocketHandler(w http.ResponseWriter, req *http.Request, newURL *url.URL) {
	// force websocket-tls
	newURL.Scheme = "wss"
	debugLog("[DEBUG] websocket upstream at", newURL.String())

	// downstream
	// Connection and Upgrade are needed
	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		log.Println("upgrade", err)
		return
	}
	defer conn.Close()

	// upstream
	req.Header.Del("Upgrade")
	req.Header.Del("Connection")
	req.Header.Del("Sec-WebSocket-Key")
	req.Header.Del("Sec-WebSocket-Version")
	req.Header.Del("Sec-WebSocket-Protocol")
	req.Header.Set("Host", req.Host)
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
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	defer connUp.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go websocketTunnel("[DEBUG] down->up", &wg, conn, connUp)
	wg.Add(1)
	go websocketTunnel("[DEBUG] up->down", &wg, connUp, conn)
	wg.Wait()
	debugLog("[DEBUG] waitgroup finished")
}

// Simplex websocket tunnel, connFrom => connTo
func websocketTunnel(logTag string, wg *sync.WaitGroup, connFrom, connTo *websocket.Conn) {
	defer wg.Done()
	for {
		messageType, p, err := connFrom.ReadMessage()
		if err != nil {
			debugLog(logTag, "t01", err)
			websocketWriteClose(connTo, err)
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
			websocketWriteClose(connFrom, err)
			return
		}
	}
}

// Detect if error is a *websocket.CloseError
func websocketIsCloseError(err error) bool {
	_, ok := err.(*websocket.CloseError)
	return ok
}

// Get the *websocket.CloseError inside of an error
func websocketCloseError(err error) *websocket.CloseError {
	if e, ok := err.(*websocket.CloseError); ok {
		return e
	} else {
		return nil
	}
}

// Forward websocket close code/text
func websocketWriteClose(conn *websocket.Conn, err error) {
	var e *websocket.CloseError
	if websocketIsCloseError(err) {
		e = websocketCloseError(err)
	} else {
		e = &websocket.CloseError{Code:websocket.CloseAbnormalClosure, Text:""}
	}
	debugLog("close code is", e.Code)
	var closeMessage []byte
	if (e.Code != websocket.CloseNoStatusReceived) &&
	   (e.Code != websocket.CloseAbnormalClosure) &&
	   (e.Code != websocket.CloseTLSHandshake) {
		closeMessage = websocket.FormatCloseMessage(e.Code, e.Text)
	} else {
		closeMessage = []byte{}
	}
	err2 := conn.WriteControl(websocket.CloseMessage, closeMessage, time.Time{})
	if err2 != nil {
		log.Println(err2)
	}
}

// Write log conditioned on config.LogDebug
func debugLog(v ...interface{}) {
	if config.LogDebug != 0 {
		log.Println(v...)
	}
}
