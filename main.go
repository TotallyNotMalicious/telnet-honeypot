package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

var channel chan []byte

func init() {
	channel = make(chan []byte, 10)
}

func main() {
	server, err := net.Listen("tcp4", ":23")
	if err != nil {
		fmt.Println("\nError whilst starting honeypot")
		return
	}
	defer server.Close()
	fmt.Println("\nHoneypot started")
	go save()

	for {
		client, err := server.Accept()
		if err != nil {
			fmt.Println("\nError whilst accepting connection")
			continue
		}
		go handler(client)
	}
}

func handler(conn net.Conn) {
	var (
		initial  = []byte{0xff, 0xfd, 0x01}
		username = []byte{0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x3a}             // username:
		password = []byte{0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x3a}             // password:
		shell    = []byte{0x61, 0x64, 0x6d, 0x69, 0x6e, 0x40, 0x63, 0x61, 0x6d, 0x3a, 0x20} // admin@cam:
	)

	report := make([]byte, 2048)

	defer func() {
		channel <- report
		conn.Close()
	}()

	fmt.Printf("\nNew connection from %s", conn.RemoteAddr().String())
	buffer, response := write(conn, initial)
	report = append(report, buffer...)
	if !response {
		return
	}
	buffer, response = write(conn, username)
	report = append(report, buffer...)
	if !response {
		return
	}
	buffer, response = write(conn, password)
	report = append(report, buffer...)
	if !response {
		return
	}
	for i := 0; i < 50; i++ {
		if !response {
			break
		}
		buffer, response = write(conn, shell)
		report = append(report, buffer...)
	}
}

func write(conn net.Conn, data []byte) ([]byte, bool) {
	_, err := conn.Write(data)
	if err != nil {
		fmt.Printf("%s - Error whilst writing data: %s", conn.RemoteAddr().String(), err.Error())
		return []byte{}, false
	}

	response, succeed := read(conn)
	if !succeed {
		return response, false
	}
	return response, true
}

func read(conn net.Conn) ([]byte, bool) {
	<-time.After(200 * time.Millisecond)
	buf := make([]byte, 4096)
	data := make([]byte, 0, 4096)

	for {
		input, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("%s - Error whilst reading data: %s", conn.RemoteAddr().String(), err.Error())
				return data, false
			}

			break
		}
		data = append(data, buf[:input]...)

		if input < 4096 {
			break
		}
	}
	return data, true
}

func save() {
	for {
		report := <-channel
		file, err := os.OpenFile("honeylogs.txt", os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("\nError whilst writing to file")
			return
		}
		output := string(report)
		file.WriteString(output)
		file.Close()
		continue
	}
}
