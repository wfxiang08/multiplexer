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
	//"encoding/hex" //Dump
)

var forwardTable map[string]map[string]string

func main() {
	content, err := ioutil.ReadFile("forwardtable.yaml")
	if err != nil {
		log.Fatalln("cannot read forwardtable")
	}
	yaml.Unmarshal(content, &forwardTable)

	log.Println("multiplexer starting...")
	addr80, err := net.ResolveTCPAddr("tcp", ":8080")
	if err != nil {
		log.Fatalln("net.resolve", err)
	}
	ln80, err := net.ListenTCP("tcp", addr80)
	if err != nil {
		log.Fatalln("net.Listen", err)
	}

	addr443, err := net.ResolveTCPAddr("tcp", ":8443")
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
			log.Println("conn", conn)
			rx := bufio.NewReader(conn)
			req, err := http.ReadRequest(rx)
			if err != nil {
				log.Println("http req", err)
			} else {
				forwardHTTP(conn, req)
			}
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
			log.Println("conn", conn)

			// TLS record
			// contentType    1 byte
			// major, minor   2 bytes
			// length         2 bytes
			// payload

			// read 5 bytes
			// read $length of payload

			rx := conn
			header := make([]byte, 5)
			n, err := io.ReadFull(rx, header)

			if (err != nil) || (n != len(header)) {
				log.Println("tls record header err", err)
			} else {
				forwardTLS(conn, header)
			}
		}
	}()
	wg.Wait()
}

func getForward(scheme, orig string) string {
	for pattern, upstream := range forwardTable[scheme] {
		matched, err := regexp.MatchString(pattern, orig)
		if (err == nil) && matched {
			return upstream
		}
	}
	return forwardTable[scheme]["default"]
}

func forwardHTTP(conn net.Conn, req *http.Request) {
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
}

func forwardTLS(conn net.Conn, header []byte) {
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
	rx := conn
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
	var offset_hostname int
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
					offset_hostname = offset_now+3
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
	// FIXME  modify request!
	// change SNI hostname to upstream name
	_, err = upstream.Write(header)
	if err != nil {
		log.Println("send failed", err)
		conn.Close()
		return
	}
	_, err = upstream.Write(payload)
	if err != nil {
		log.Println("send failed", err)
		conn.Close()
		return
	}
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
