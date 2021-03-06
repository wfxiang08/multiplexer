// only suport client with SNI
package main

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var configFile = flag.String("config", "mp2.yaml", "path to config file")

var config Config

type Target struct {
	Port            string `yaml:"port"`
	Host            string `yaml:"host"`
	OverrideHost    bool   `yaml:"override_host"`
	OverrideHostURL bool   `yaml:"override_host_url"`
	NoTLS           bool   `yaml:"notls"`
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
	DefaultHost  string            `yaml:"default_host"`
	SNICompat    bool              `yaml:"sni_compat"`
}

// logrotate?
var LOG_FILE = "mp2.log"
var log_fh *os.File

var c_reload chan os.Signal

var httpClient = &http.Client{
	// FIXME: no timeout
	Timeout: 0 * time.Second,
	Transport: &http.Transport{
		//Proxy: nil,
		//Dial: (&net.Dialer{
		//	Timeout:   30 * time.Second,
		//	KeepAlive: 30 * time.Second,
		//}).Dial,
		//DialTLS:               nil,
		//TLSHandshakeTimeout:   10 * time.Second,
		//ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			//	//NextProtos: []string{"h2", "http/1.1"},
		},
		//TLSNextProto: nil,
	},
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// FIXME strip port and check origin == host?
		debugLog("Origin:", r.Header.Get("Origin"))
		debugLog("Host:", r.Host)
		return true
	},
}

var websocketDialer = &websocket.Dialer{
	Proxy:           nil,
	TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
}

func openLog(logfile string) {
	fh, err := os.OpenFile(logfile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0640)
	if err != nil {
		log.Fatalln("cannot open logfile:", err)
	}
	log.SetOutput(fh)
	log.Printf("Current config: %#v\n", config)
	if log_fh != nil {
		log_fh.Close()
	}
	log_fh = fh
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
	openLog(LOG_FILE)
	//defer fh.Close()?

	if config.SkipVerify != 0 {
		httpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
		websocketDialer.TLSClientConfig.InsecureSkipVerify = true
	}

	// config http client for http2
	err = http2.ConfigureTransport(httpClient.Transport.(*http.Transport))
	if err != nil {
		log.Fatalln(err)
	}
	debugLogf("try1 %#v\n", httpClient)
	debugLogf("try1 %#v\n", httpClient.Transport)
	debugLogf("try1 %#v\n", httpClient.Transport.(*http.Transport).TLSClientConfig)

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
			} else if config.SNICompat {
				return mapCert[config.DefaultHost], nil
			}
			return nil, errors.New("<" + clientHello.ServerName + "> not found")
		},
		NameToCertificate: mapCert,
		Certificates:      nil,
		NextProtos:        []string{"h2", "http/1.1"},
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

	c_reload = make(chan os.Signal)
	signal.Notify(c_reload, syscall.SIGHUP)
	go func() {
		for {
			select {
			case s := <-c_reload:
				openLog(LOG_FILE)
				log.Println("received", s)
				log.Println("reopened logfile")
			}
		}
	}()
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

// Strip ":port" from req.Host if present, otherwise just return req.Host
func parseHost(req *http.Request) string {
	//if req.Host == "" {
	//	log.Fatalln("req.Host empty") // net/http server set req.Host automatically
	//}
	// Extract the hostname part req.Host == "some.hostname.net:1234"
	host_strip, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		// If req.Host doesn't contain any port part.
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

	// The mangling of req.Host and req.URL
	// req.Host is for the "Host:" header
	// req.URL is for DNS resolving and path/query part.

	// use case-insensitive comparison for host name
	upstream, ok := config.ForwardTable[strings.ToLower(host)]
	if !ok {
		upstream = config.ForwardTable["default"]
	}
	port := upstream.Port
	if upstream.Host != "" {
		host = upstream.Host
	}

	// Construct the URL on the internal web server
	hostport := net.JoinHostPort(host, port)
	// Take the original URL (keeping only the the path/query part)
	newURL, _ := req.URL.Parse("")
	newURL.Scheme = "https"
	if upstream.NoTLS {
		newURL.Scheme = "http"
		// If using plaintext, restrict the upstream server to be localhost
		hostport = net.JoinHostPort("127.0.0.1", port)
	}
	newURL.Host = hostport

	// Don't change "Host:" header: use the original value from req,
	// necessary for external service running on non-standard ports.
	//req.Host = host

	// (?) In case when we want to act as a reverse proxy to some arbitrary website
	if upstream.OverrideHost {
		req.Host = upstream.Host
	}
	// FIXME: document here
	if upstream.OverrideHostURL {
		hostport := net.JoinHostPort(upstream.Host, port)
		newURL.Host = hostport
	}
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
	//log.Println(connectionList)

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
	//log.Printf("%#v\n", httpClient.Transport)
	//log.Printf("%#v\n", httpClient.Transport.(*http.Transport).TLSClientConfig)
	//resp, err := http.DefaultClient.Do(req)
	//log.Println(http.DefaultClient)
	if err == nil {
		debugLog(resp.Proto)
	}
	defer resp.Body.Close()
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
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println("io.Copy err:", err)
	}
	// FIXME process trailers?
	if len(resp.Trailer) > 0 {
		log.Println("response has trailer?")
	}
}

// Combine header lines, and split at "," (only useful for certain headers)
func parseHeader(header http.Header, key string) []string {
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
	debugLog("websocket upstream at", newURL.String())

	// downstream
	// Connection and Upgrade are needed
	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		log.Println("upgrade", err)
		return
	}
	defer conn.Close()

	// To send to upstream server (websocket)
	// several headers need to be removed for websocketDialer.Dial() to avoid
	// duplicate. (TODO: check for relevant RFCs)
	req.Header.Del("Upgrade")
	req.Header.Del("Connection")
	req.Header.Del("Sec-WebSocket-Key")
	req.Header.Del("Sec-WebSocket-Version")
	req.Header.Del("Sec-WebSocket-Protocol")
	req.Header.Del("Sec-Websocket-Extensions")

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
			// No need according to doc
			//respUp.Body.Close()
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	defer connUp.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go websocketTunnel("down->up", &wg, conn, connUp)
	wg.Add(1)
	go websocketTunnel("up->down", &wg, connUp, conn)
	wg.Wait()
	debugLog("waitgroup finished")
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
		e = &websocket.CloseError{Code: websocket.CloseAbnormalClosure, Text: ""}
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
		v = append([]interface{}{"[DEBUG]"}, v...)
		log.Println(v...)
	}
}

func debugLogf(format string, v ...interface{}) {
	if config.LogDebug != 0 {
		log.Printf("[DEBUG] "+format, v...)
	}
}
