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
