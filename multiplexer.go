// webserver sudo setcap cap_net_bind_service=ep multiplexer
package main

import (
	"net"
	"log"
	"bufio"
	"net/http"
	"io"
	"gopkg.in/yaml.v2"
	"regexp"
	"io/ioutil"
	"sync"
	"fmt"
	//"encoding/hex" //Dump
	"strings"
)

//var forwardTable map[string]map[string]string
var forwardTable interface{}
var config map[string]interface{}
var port int
var porttls int

func main() {
	content, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Fatalln("cannot read config")
	}
	yaml.Unmarshal(content, &config)
	//forwardTable = map[string]interface{}(config["forwardtable"].(map[interface{}]interface{}))
	forwardTable = config["forwardtable"]
	port = config["port"].(int)
	porttls = config["porttls"].(int)
	//log.Printf("%t\n%#v\n", port, porttls)

	log.Println("multiplexer starting...")
	addr80, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalln("net.resolve", err)
	}
	ln80, err := net.ListenTCP("tcp", addr80)
	if err != nil {
		log.Fatalln("net.Listen", err)
	}

	addr443, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", porttls))
	if err != nil {
		log.Fatalln("net.resolve", err)
	}
	ln443, err := net.ListenTCP("tcp", addr443)
	if err != nil {
		log.Fatalln("net.Listen", err)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln80.Accept()
			if err != nil {
				log.Println("Accept", err)
			}
			log.Println("conn to", conn.LocalAddr(), "from", conn.RemoteAddr())

			//forwardHTTP(conn)
			convertHTTPtoTLS(conn)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln443.Accept()
			if err != nil {
				log.Println("Accept", err)
			}
			log.Println("conn to", conn.LocalAddr(), "from", conn.RemoteAddr())

			forwardTLS(conn)
		}
	}()
	wg.Wait()
}

func getForward(scheme, orig string) string {
	for pattern, upstream := range forwardTable.(map[interface{}]interface{})[scheme].(map[interface{}]interface{}) {
		log.Println("pattern", pattern.(string))
		if pattern == "default" {
			continue
		}
		matched, err := regexp.MatchString(pattern.(string), orig)
		if (err == nil) && matched {
			log.Println("matched", pattern.(string))
			return upstream.(string)
		}
	}
	return forwardTable.(map[interface{}]interface{})[scheme].(map[interface{}]interface{})["default"].(string)
}

func forwardHTTP(conn net.Conn) {
	rx := bufio.NewReader(conn)
	req, err := http.ReadRequest(rx)
	if err != nil {
		log.Println("http req", err)
		conn.Close()
		return
	}

	log.Println(req)
	var host string
	if req.Host != "" {
		host = req.Host
	} else {
		host = req.URL.Host
	}
	log.Println("host is ", host)
	upstreamAddr := getForward("http", host)
	upstream, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		log.Println("upstream offline", err)
		conn.Close()
		return
	}
	// FIXME modify request?
	req.Write(upstream)
	go func() {
		defer upstream.Close()
		defer conn.Close()
		io.Copy(conn, upstream)
	}()
	go func() {
		defer conn.Close()
		defer upstream.Close()
		io.Copy(upstream, conn)
	}()
}

// todo
func convertHTTPtoTLS(conn net.Conn) {
	rx := bufio.NewReader(conn)
	req, err := http.ReadRequest(rx)
	if err != nil {
		log.Println("http req", err)
		conn.Close()
		return
	}

	log.Println(req)
	var host string
	if req.Host != "" {
		host = req.Host
	} else {
		host = req.URL.Host
	}
	log.Println("host is ", host)

	host_replace := strings.Replace(host, fmt.Sprintf(":%d",port), fmt.Sprintf(":%d",porttls), -1)

	//req.URL.Host = host
	//req.URL.Scheme = "https"
	newURL, err := req.URL.Parse("")
	newURL.Host = host_replace
	newURL.Scheme = "https"

	bodyString := ""
	if req.Method == "GET" {
		bodyString = "<a href=\"" + htmlEscape(newURL.String()) + "\">" + "Moved Permanently" + "</a>.\n"
	}

	resp := http.Response{}
	resp.StatusCode = http.StatusMovedPermanently
	resp.ProtoMajor = req.ProtoMajor
	resp.ProtoMinor = req.ProtoMinor
	resp.Request = req
	resp.TransferEncoding = req.TransferEncoding
	resp.Trailer = nil
	resp.Body = ioutil.NopCloser(strings.NewReader(bodyString))
	resp.Header = make(http.Header)
	resp.Header.Set("Location", newURL.String())
	resp.ContentLength = -1
	//http.Redirect(conn, req, req.URL.String(), http.StatusMovedPermanently)
	err = resp.Write(conn)
	if err != nil {
		log.Println("resp", err)
	}
	conn.Close()
}

func forwardTLS(conn net.Conn) {
	// TLS record
	// contentType    1 byte
	// major, minor   2 bytes
	// length         2 bytes
	// payload

	// read 5 bytes
	// read $length of payload
	rx := conn
	header := make([]byte, 5)
	{
		n, err := io.ReadFull(rx, header)

		if (err != nil) || (n != len(header)) {
			log.Println("tls record header err", err)
			conn.Close()
			return
		}
	}



	var host string
	// header[0] == 22 // Handshake
	// header[1]
	// header[2]
	typ := header[0]
	vers := uint16(header[1])<<8 | uint16(header[2])
	n := int(header[3])<<8 | int(header[4])
	//log.Println("header", header)
	//log.Println("n", n)

	_ = vers
	if typ != 22 {
		// not handshake
		conn.Close()
		return
	}
	if n > 16384 + 2048 {
		// too large FIXME shutdown
		conn.Close()
		return
	}
	payload := make([]byte, n)
	n2, err := io.ReadFull(rx, payload)
	if (err != nil) || (n2 != n) {
		// FIXME fail, shutdown
		conn.Close()
		return
	}
	//log.Print("payload\n", hex.Dump(payload), "\n")
	// payload:
	//
	// 1b  handshake type  [0]
	// 3b  length == n-4   [1-3]
	// 2b  version         [4-5]
	// 32b random          [6-37]
	// 1b  session id length [38]
	// +xx                   [39...38+xx]
	// 2b  cipher suite length
	// +xx
	// 1b  compression method length
	// +xx
	// 2b  extension length
	//
	// 2b  ext1-type
	// 2b  ext1-len
	// +xx
	offset_sid := 38
	n_sid := int(payload[offset_sid])
	//log.Println("n_sid", n_sid)
	offset_cipher := offset_sid + 1 + n_sid
	//log.Println("offset_cipher", offset_cipher)
	n_cipher := int(payload[offset_cipher]) << 8 | int(payload[offset_cipher+1])
	offset_comp := offset_cipher + 2 + n_cipher
	n_comp := int(payload[offset_comp])
	offset_ext := offset_comp + 1 + n_comp
	n_ext := int(payload[offset_ext])<<8 | int(payload[offset_ext+1])
	_ = n_ext
	offset_current := offset_ext + 2
	for offset_current < n {
		//log.Println("offset_current", offset_current)
		typ_current := int(payload[offset_current])<<8 | int(payload[offset_current+1])
		n_current := int(payload[offset_current+2])<<8 | int(payload[offset_current+3])
		//log.Print("\n", hex.Dump(payload[offset_current:offset_current+4+n_current]),"\n")
		if typ_current == 0 { // server_name extension
			offset_now := offset_current + 4
			// 2b server name list len
			n_servername_list := int(payload[offset_now])<<8 | int(payload[offset_now+1])
			// [ 1b 2b +len ]  servername type, servername len, servername
			offset_now += 2
			for offset_now < offset_current + 4 + n_servername_list {
				typ_servername := int(payload[offset_now])
				n_servername := int(payload[offset_now+1])<<8 | int(payload[offset_now+2])
				servername := payload[offset_now+3:offset_now+3+n_servername]
				log.Println("SNI", typ_servername, string(servername))
				if typ_servername == 0 {
					host = string(servername)
				}
				offset_now += 3+n_servername
			}
		}
		offset_current += 4 + n_current
	}
	upstreamAddr := getForward("https", host)
	log.Println("upstreamAddr", upstreamAddr)
	upstream, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		log.Println("upstream offline", err)
		conn.Close()
		return
	}
	// FIXME dont modify request!

	_, err = upstream.Write(append(header, payload...))
	if err != nil {
		log.Println("send failed", err)
		conn.Close()
		return
	}
	// FIXME why...
	go func() {
		defer upstream.Close()
		defer conn.Close()
		io.Copy(conn, upstream)
	}()
	go func() {
		defer conn.Close()
		defer upstream.Close()
		io.Copy(upstream, conn)
	}()
}

func decodeInt16(payload []byte) int {
	n := int(payload[0])<<8 | int(payload[1])
	return n
}

func encodeInt16(payload []byte, n int) {
	payload[0] = byte(n>>8)
	payload[1] = byte(n%256)
}

func decodeInt24(payload []byte) int {
	n := int(payload[0])<<16 | int(payload[1])<<8 | int(payload[2])
	return n
}

func encodeInt24(payload []byte, n int) {
	payload[0] = byte(n>>16)
	payload[1] = byte((n>>8)%256)
	payload[2] = byte(n%256)
}

var htmlReplacer = strings.NewReplacer(
    "&", "&amp;",
    "<", "&lt;",
    ">", "&gt;",
    // "&#34;" is shorter than "&quot;".
    `"`, "&#34;",
    // "&#39;" is shorter than "&apos;" and apos was not in HTML until HTML5.
    "'", "&#39;",
)

func htmlEscape(s string) string {
    return htmlReplacer.Replace(s)
}
