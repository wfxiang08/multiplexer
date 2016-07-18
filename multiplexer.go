package main

import (
	"net"
	"log"
)

func main() {
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
	}
}
