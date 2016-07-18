package main

import (
	"net"
	"log"
	"bufio"
	"net/http"
	"io"
)

func main() {
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
			log.Println(req)
			var host string
			if req.Host != "" {
				host = req.Host
			} else {
				host = req.URL.Host
			}
			log.Println("host is ", host)
			upstream, err := net.Dial("tcp", "localhost:80")
			if err != nil {
			}
			req.Write(upstream)
			go func() {
				defer upstream.Close()
				defer conn.Close()
				io.Copy(conn, upstream)
			}()
		}
	}
}
