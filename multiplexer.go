package main

import (
	"net"
	"log"
)

func main() {
	ln80, err := net.Listen("tcp", ":8080")
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
