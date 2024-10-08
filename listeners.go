// Copyright 2023-2024 Mike Carlton
// Released under terms of the MIT License:
//   http://www.opensource.org/licenses/mit-license.php

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	USAGE = "Usage: %s [-h] [-q] [-x] [-4] [-6] [-u] [-t] [-j] [PORT(S) | USERNAME | @PID]\n"
	UDPv4 = "/proc/net/udp"
	UDPv6 = "/proc/net/udp6"
	TCPv4 = "/proc/net/tcp"
	TCPv6 = "/proc/net/tcp6"
)

type PortNumber int
type OwnerId int // PID or UID

type Protocol struct {
	Files       []string
	ListenState string
	Enabled     bool
	Listeners   []Listener // flattened list of listening sockets
}

type Socket struct {
	Address string
	UID     int
	Inode   int
}

type OwnerInfo struct {
	User      string
	Cmd       []string
	Addresses map[string]bool
}

type Listener struct {
	Protocol  string   `json:"protocol"`
	Port      int      `json:"port"`
	Addresses []string `json:"addresses"`
	User      string   `json:"user"`
	PID       int      `json:"pid,omitempty"`
	Cmd       []string `json:"command,omitempty"`
}

// adds entry to listeners if the socket is in listening state
// https://www.kernel.org/doc/html/v5.8/networking/proc_net_tcp.html
func collect(entry string, listeners map[PortNumber][]Socket, listenState string) {
	fields := strings.Fields(entry)
	localAddress := fields[1]
	state := fields[3]
	uid := fields[7]
	inode := fields[9]

	if state == listenState {
		address, portStr, found := strings.Cut(localAddress, ":")
		if !found {
			panic(fmt.Sprintf("invalid address string: %s", localAddress))
		}

		var port PortNumber
		_, err := fmt.Sscanf(portStr, "%x", &port)
		if err != nil {
			panic(fmt.Sprintf("invalid port: %d", port))
		}

		listeners[port] = append(listeners[port], Socket{
			Address: unpackIP(address),
			UID:     mustAtoi(uid),
			Inode:   mustAtoi(inode),
		})
	}
}

func unpackIP(data string) string {
	var ip net.IP

	switch len(data) {
	case 8:
		bytes := [4]byte{}
		_, err := fmt.Sscanf(data, "%2x%2x%2x%2x", &bytes[3], &bytes[2], &bytes[1], &bytes[0])
		if err != nil {
			panic(fmt.Sprintf("unable to scan hex IPv4 '%s'", data))
		}
		ip = net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
	case 32:
		bytes := [16]byte{}
		_, err := fmt.Sscanf(data, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
			&bytes[3], &bytes[2], &bytes[1], &bytes[0],
			&bytes[7], &bytes[6], &bytes[5], &bytes[4],
			&bytes[11], &bytes[10], &bytes[9], &bytes[8],
			&bytes[15], &bytes[14], &bytes[13], &bytes[12],
		)
		if err != nil {
			panic(fmt.Sprintf("unable to scan hex IPv6 '%s'", data))
		}
		ip = net.IP(bytes[:])
	default:
		panic(fmt.Sprintf("invalid data length: %d", len(data)))
	}

	return ip.String()
}

func mustAtoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return i
}

// return username for user id
func username(uid int) string {
	user, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return "----"
	}
	return user.Username
}

func isRoot() bool {
	return os.Getuid() == 0
}

// return process name for process id
func processName(pid int, extended bool) []string {
	if pid < 0 {
		return []string{}
	}
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	if !exists(path) {
		return []string{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	words := strings.Split(string(data), "\000")
	numWords := len(words)
	if numWords > 0 && len(words[numWords-1]) == 0 {
		words = words[:numWords-1]
	}
	if !extended {
		words = words[:1]
	}
	return words
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func SetField(protocols map[string]*Protocol, name string, field string, value interface{}) {
	protocol, ok := protocols[name]
	if !ok {
		panic(fmt.Sprintf("protocol %s not found", name))
	}

	switch field {
	case "Files":
		files, ok := value.([]string)
		if !ok {
			panic(fmt.Sprintf("invalid value for Files: %v", value))
		}
		protocol.Files = files
	case "Enabled":
		enabled, ok := value.(bool)
		if !ok {
			panic(fmt.Sprintf("invalid value for Enabled: %v", value))
		}
		protocol.Enabled = enabled
	default:
		panic(fmt.Sprintf("unknown field: %s", field))
	}

	protocols[name] = protocol
}

func main() {
	protocols := map[string]*Protocol{
		"udp": {Files: []string{UDPv4, UDPv6}, ListenState: "07", Enabled: true},
		"tcp": {Files: []string{TCPv4, TCPv6}, ListenState: "0A", Enabled: true},
	}

	singlePort := 0 // 0 is reserved in UDP and TCP
	singleUser := ""
	singlePID := -1
	quiet := false
	extended := false
	jsonOutput := false

	socketRE := regexp.MustCompile(`socket:\[(\d+)\]`)
	procRE := regexp.MustCompile(`^/proc/(\d+)/`)
	userRE := regexp.MustCompile(`^[a-z][-a-z]*$`)
	pidRE := regexp.MustCompile(`^@\d+$`)

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-4":
			SetField(protocols, "tcp", "Files", []string{TCPv4})
			SetField(protocols, "udp", "Files", []string{UDPv4})
		case "-6":
			SetField(protocols, "tcp", "Files", []string{TCPv6})
			SetField(protocols, "udp", "Files", []string{UDPv6})
		case "-j":
			jsonOutput = true
		case "-t":
			SetField(protocols, "tcp", "Enabled", true)
			SetField(protocols, "udp", "Enabled", false)
		case "-u":
			SetField(protocols, "udp", "Enabled", true)
			SetField(protocols, "tcp", "Enabled", false)
		case "-q":
			quiet = true
		case "-x":
			extended = true
		case "-h":
			fmt.Printf(USAGE, os.Args[0])
			fmt.Println("    -4: show only IPv4 listeners")
			fmt.Println("    -6: show only IPv6 listeners")
			fmt.Println("    -u: show only UDP listeners")
			fmt.Println("    -t: show only TCP listeners")
			fmt.Println("    -q: no output, exit status only")
			fmt.Println("    -x: show extended process info (requires root access)")
			fmt.Println("    -j: JSON output")
			fmt.Println("    -h: show this help")
			fmt.Println("    PORTS: show only listeners for PORTS")
			fmt.Println("    USERNAME: show only processes owned by USERNAME")
			fmt.Println("    ^PID: show only listeners owned by process PID (requires root access)")
			fmt.Println("  PORT(S) is a comma-separated list of ports or port ranges, e.g. '443' or '80,8000-8080'")
			fmt.Println("  Exits with status 0 (success) if any listeners are found, else exits with status 1")
			os.Exit(0)
		default:
			if pidRE.MatchString(os.Args[i]) {
				singlePID = mustAtoi(os.Args[i][1:])
			} else if userRE.MatchString(os.Args[i]) {
				singleUser = os.Args[i]
			} else if port, err := strconv.Atoi(os.Args[i]); err == nil {
				singlePort = port
			} else {
				fmt.Fprintf(os.Stderr, USAGE, os.Args[0])
				os.Exit(1)
			}
		}
	}

	if (extended || singlePID >= 0) && !isRoot() {
		fmt.Fprintf(os.Stderr, "Showing process info or filtering on PID requires root access\n")
		os.Exit(1)
	}

	// map inodes to pids by scanning /proc/*/fd (requires root)
	inodeToPid := map[int]OwnerId{}
	if isRoot() {
		paths, _ := filepath.Glob("/proc/[0-9]*/fd/*")
		for _, path := range paths {
			if target, err := os.Readlink(path); err == nil {
				targetMatches := socketRE.FindStringSubmatch(target)
				if targetMatches != nil {
					inode := mustAtoi(targetMatches[1])
					procMatches := procRE.FindStringSubmatch(path)
					if procMatches != nil {
						inodeToPid[inode] = OwnerId(mustAtoi(procMatches[1]))
					}
				}
			}
		}
	}

	exitCode := 1
	for _, name := range []string{"udp", "tcp"} {
		protocol := protocols[name]
		if !protocol.Enabled {
			continue
		}

		inputLines := []string{}
		for _, filename := range protocol.Files {
			if !exists(filename) { // e.g. if system does not support IPv6
				continue
			}

			data, err := os.ReadFile(filename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unable to read %s socket file '%s': %v\n", name, filename, err)
				os.Exit(1)
			}

			// skip the header line
			dataLines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
			inputLines = append(inputLines, dataLines[1:]...)
		}

		// collect listening sockets
		sockets := map[PortNumber][]Socket{}
		for _, line := range inputLines {
			collect(line, sockets, protocol.ListenState)
		}

		keys := make([]PortNumber, 0, len(sockets))
		for k := range sockets {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return keys[i] < keys[j]
		})

		// group matches
		for _, port := range keys {
			if singlePort != 0 && port != PortNumber(singlePort) {
				continue
			}
			owners := map[OwnerId]*OwnerInfo{}

			// we want to group addresses listening on a port by pid (or by user id when pid not available)
			// note that a process can listen to a port on multiple addresses and more than one process
			// can listen on a given port or even a (address, port) tuple as long as same user
			for _, listener := range sockets[port] {
				user := username(listener.UID)
				if singleUser != "" && user != singleUser {
					continue
				}

				var owner *OwnerInfo
				if isRoot() {
					pid, ok := inodeToPid[listener.Inode]
					if !ok {
						// socket could have been created in the small window between making map and scanning sockets
						fmt.Fprintf(os.Stderr, "Unable to find process for inode %d", listener.Inode)
						pid = -1
					}
					if singlePID != -1 && pid != OwnerId(singlePID) {
						continue
					}

					if owner = owners[pid]; owner == nil {
						owner = &OwnerInfo{
							User:      user,
							Cmd:       processName(int(pid), extended),
							Addresses: make(map[string]bool),
						}
						owners[pid] = owner
					}
				} else {
					if owner = owners[OwnerId(listener.UID)]; owner == nil {
						owner = &OwnerInfo{
							User:      user,
							Cmd:       []string{},
							Addresses: make(map[string]bool),
						}
						owners[OwnerId(listener.UID)] = owner
					}
				}
				owner.Addresses[listener.Address] = true
			}

			for ownerId, owner := range owners {
				addresses := make([]string, 0, len(owner.Addresses))
				for address := range owner.Addresses {
					addresses = append(addresses, address)
				}
				sort.Slice(addresses, func(i, j int) bool {
					return addresses[i] < addresses[j]
				})
				listener := Listener{
					Protocol:  name,
					Port:      int(port),
					Addresses: addresses,
					User:      owner.User,
				}
				if isRoot() {
					listener.PID = int(ownerId)
					listener.Cmd = owner.Cmd
				}
				protocol.Listeners = append(protocol.Listeners, listener)
			}
		}

		if len(protocol.Listeners) > 0 {
			exitCode = 0
		}
	}

	if quiet {
		os.Exit(exitCode)
	}

	// display results
	if jsonOutput {
		fmt.Printf("[")
		separator := ""
		for _, name := range []string{"udp", "tcp"} {
			listeners := protocols[name].Listeners
			for _, listener := range listeners {
				json, err := json.Marshal(listener)
				if err != nil {
					panic(err)
				}
				fmt.Printf("%s\n  %s", separator, string(json))
				separator = ","
			}
		}
		fmt.Printf("\n]\n")
	} else {
		stanza := 0
		for _, name := range []string{"udp", "tcp"} {
			header := []string{strings.ToUpper(name), "ADDR", "USER"}
			if isRoot() {
				header = append(header, "PID", "CMD")
			}
			lines := [][]string{header}

			for _, listener := range protocols[name].Listeners {
				line := []string{fmt.Sprintf("%d", listener.Port), strings.Join(listener.Addresses, ", "), listener.User}
				if isRoot() {
					line = append(line, fmt.Sprintf("%d", listener.PID), strings.Join(listener.Cmd, " "))
				}
				lines = append(lines, line)
			}

			// print output
			if len(lines) <= 1 {
				continue
			}

			if stanza > 0 {
				fmt.Println()
			}
			stanza = 1

			// find max width of each column
			widths := make([]int, len(lines[0]))
			for _, line := range lines {
				for i, field := range line {
					widths[i] = max(widths[i], len(field))
				}
			}

			// left-justify certain columns
			widths[1] *= -1
			widths[2] *= -1

			for _, line := range lines {
				spacer := ""
				for i, width := range widths {
					if i == len(widths)-1 { // last column does not need width
						width = 0
					}
					fmt.Printf("%s%*s", spacer, width, line[i])
					spacer = " "
				}
				fmt.Println()
			}
		}
	}

	// exit success if any matches were found
	os.Exit(exitCode)
}
