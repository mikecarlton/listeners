package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
 	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: go run main.go <tcp|udp> <interface> <port>")
		return
	}

	protocol := os.Args[1]
	iface := os.Args[2]
	port := os.Args[3]

	if protocol != "tcp" && protocol != "udp" {
		fmt.Println("Error: Protocol must be either 'tcp' or 'udp'")
		return
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber <= 0 || portNumber > 65535 {
		fmt.Println("Error: Invalid port number")
		return
	}

	if protocol == "tcp" {
		startTCPServer(iface, portNumber)
	} else if protocol == "udp" {
		startUDPServer(iface, portNumber)
	}
}

func startTCPServer(iface string, port int) {
	addr := net.JoinHostPort(iface, strconv.Itoa(port))

	// Manually create a listener with SO_REUSEPORT option
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		fmt.Printf("Error resolving TCP address: %v\n", err)
		return
	}

	// Create a raw socket
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		fmt.Printf("Error creating socket: %v\n", err)
		return
	}

	// Enable SO_REUSEPORT
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		fmt.Printf("Error setting SO_REUSEPORT: %v\n", err)
		return
	}

	// Bind to the address
	sockAddr := unix.SockaddrInet4{Port: port}
	copy(sockAddr.Addr[:], tcpAddr.IP.To4())

	if err := unix.Bind(fd, &sockAddr); err != nil {
		fmt.Printf("Error binding to address: %v\n", err)
		return
	}

	// Start listening
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		fmt.Printf("Error listening on socket: %v\n", err)
		return
	}

	fmt.Printf("TCP server listening on %s:%d with SO_REUSEPORT enabled...\n", iface, port)

	// Accept and handle connections
	for {
		newFd, _, err := unix.Accept(fd)
		if err != nil {
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}

		go handleTCPConnection(newFd)
	}
}

func handleTCPConnection(fd int) {
	defer unix.Close(fd)

	buf := make([]byte, 1024)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			fmt.Printf("Error reading from connection: %v\n", err)
			return
		}

		if n == 0 {
			fmt.Println("Connection closed")
			return
		}

		_, err = unix.Write(fd, buf[:n])
		if err != nil {
			fmt.Printf("Error writing to connection: %v\n", err)
			return
		}
	}
}

func startUDPServer(iface string, port int) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(iface),
		Port: port,
	}

	// Create a UDP listener with SO_REUSEPORT enabled
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		fmt.Printf("Error creating UDP socket: %v\n", err)
		return
	}

	// Enable SO_REUSEPORT for UDP
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		fmt.Printf("Error setting SO_REUSEPORT on UDP socket: %v\n", err)
		return
	}

	// Bind to the address
	sockAddr := unix.SockaddrInet4{Port: port}
	copy(sockAddr.Addr[:], addr.IP.To4())

	if err := unix.Bind(fd, &sockAddr); err != nil {
		fmt.Printf("Error binding to UDP address: %v\n", err)
		return
	}

	fmt.Printf("UDP server listening on %s:%d with SO_REUSEPORT enabled...\n", iface, port)

	// Buffer for reading UDP data
	buf := make([]byte, 1024)
	for {
		// Read data from the connection
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			fmt.Printf("Error reading from UDP connection: %v\n", err)
			continue
		}

		// Echo the data back
		err = unix.Sendto(fd, buf[:n], 0, &sockAddr)
		if err != nil {
			fmt.Printf("Error sending to UDP connection: %v\n", err)
			return
		}
	}
}
