// Copyright 2023-2024 Mike Carlton
// Released under terms of the MIT License:
//   http://www.opensource.org/licenses/mit-license.php

package main

import (
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
	USAGE = "Usage: %s [-h] [-q] [-x] [-4] [-6] [-u] [-t] [PORT_NUMBER | USERNAME | @PID]\n"
	UDPv4 = "/proc/net/udp"
	UDPv6 = "/proc/net/udp6"
	TCPv4 = "/proc/net/tcp"
	TCPv6 = "/proc/net/tcp6"
)

type Family struct {
	Files       []string `json:"files"`
	ListenState string   `json:"listen_state"`
	Enabled     bool     `json:"enabled"`
}

type Listener struct {
	Address string `json:"address"`
	UID     int    `json:"uid"`
	Inode   int    `json:"inode"`
}

type ProcessInfo struct {
	User      string   `json:"user"`
	Cmd       string   `json:"cmd"`
	Addresses []string `json:"addresses"`
}

// adds entry to listeners if the socket is in listening state
// https://www.kernel.org/doc/html/v5.8/networking/proc_net_tcp.html
func collect(entry string, listeners map[int][]Listener, listenState string) {
	fields := strings.Fields(entry)
	localAddress := fields[1]
	st := fields[3]
	uid := fields[7]
	inode := fields[9]

	if st == listenState {
		address, portStr, found := strings.Cut(localAddress, ":")
		if !found {
			panic(fmt.Sprintf("invalid localAddress: %s", localAddress))
		}

		var port int
		_, err := fmt.Sscanf(portStr, "%x", &port)
		if err != nil {
			panic(fmt.Sprintf("invalid port: %d", port))
		}

		listeners[port] = append(listeners[port], Listener{
			Address: unpackIP(address, len(address)/8),
			UID:     mustAtoi(uid),
			Inode:   mustAtoi(inode),
		})
	}
}

func unpackIP(data string, words int) string {
	var ip net.IP

	switch words {
	case 1:
		bytes := [4]byte{}
		_, err := fmt.Sscanf(data, "%2x%2x%2x%2x", &bytes[3], &bytes[2], &bytes[1], &bytes[0])
		if err != nil {
			panic(fmt.Sprintf("unable to scan hex IPv4 '%s'", data))
		}
		ip = net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
	case 4:
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
		panic(fmt.Sprintf("invalid words count: %d", words))
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
func processName(pid int, extended bool) string {
	if pid < 0 {
		return ""
	}
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	if !exists(path) {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	words := strings.Split(string(data), "\000")
	numWords := len(words)
	if numWords > 0 && len(words[numWords-1]) == 0 {
		words = words[:numWords-1]
	}
	if extended {
		return strings.Join(words, " ")
	}
	return words[0]
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func SetField(families map[string]Family, name string, field string, value interface{}) {
	family, ok := families[name]
	if !ok {
		panic(fmt.Sprintf("family %s not found", name))
	}

	switch field {
	case "Files":
		files, ok := value.([]string)
		if !ok {
			panic(fmt.Sprintf("invalid value for Files: %v", value))
		}
		family.Files = files
	case "Enabled":
		enabled, ok := value.(bool)
		if !ok {
			panic(fmt.Sprintf("invalid value for Enabled: %v", value))
		}
		family.Enabled = enabled
	default:
		panic(fmt.Sprintf("unknown field: %s", field))
	}

	families[name] = family
}

func main() {
	families := map[string]Family{
		"udp": {Files: []string{UDPv4, UDPv6}, ListenState: "07", Enabled: true},
		"tcp": {Files: []string{TCPv4, TCPv6}, ListenState: "0A", Enabled: true},
	}

	singlePort := 0 // 0 is reserved in UDP and TCP
	singleUser := ""
	singlePID := -1
	quiet := false
	extended := false

	socketRE := regexp.MustCompile(`socket:\[(\d+)\]`)
	procRE := regexp.MustCompile(`^/proc/(\d+)/`)
	userRE := regexp.MustCompile(`^[a-z][-a-z]*$`)
	pidRE := regexp.MustCompile(`^@\d+$`)

	// Command-line argument parsing
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-4":
			SetField(families, "tcp", "Files", []string{TCPv4})
			SetField(families, "udp", "Files", []string{UDPv4})
		case "-6":
			SetField(families, "tcp", "Files", []string{TCPv6})
			SetField(families, "udp", "Files", []string{UDPv6})
		case "-t":
			SetField(families, "tcp", "Enabled", true)
			SetField(families, "udp", "Enabled", false)
		case "-u":
			SetField(families, "udp", "Enabled", true)
			SetField(families, "tcp", "Enabled", false)
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
			fmt.Println("    -h: show this help")
			fmt.Println("    PORT_NUMBER: show only listeners for PORT")
			fmt.Println("    USERNAME: show only processes owned by USERNAME")
			fmt.Println("    ^PID: show only listeners owned by process PID (requires root access)")
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
	inodeToPid := map[int]int{}
	if isRoot() {
		paths, _ := filepath.Glob("/proc/[0-9]*/fd/*")
		for _, path := range paths {
			if target, err := os.Readlink(path); err == nil {
				targetMatches := socketRE.FindStringSubmatch(target)
				if targetMatches != nil {
					inode := mustAtoi(targetMatches[1])
					procMatches := procRE.FindStringSubmatch(path)
					if procMatches != nil {
						inodeToPid[inode] = mustAtoi(procMatches[1])
					}
				}
			}
		}
	}

	matchResult := 1 // exit 1 if no matches
	stanza := 0
	for name, family := range families {
		if !family.Enabled {
			continue
		}

		listeners := map[int][]Listener{}
		inputLines := []string{}
		for _, file := range family.Files {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unable to read socket file '%s': %v\n", file, err)
				os.Exit(1)
			}

			// skip the header line
			dataLines := strings.Split(string(data), "\n")
			inputLines = append(inputLines, dataLines[1:]...)
		}

		// collect listeners
		for _, line := range inputLines {
			if len(line) > 0 {
				collect(line, listeners, family.ListenState)
			}
		}

		// format output
		header := []string{strings.ToUpper(name), "ADDR", "USER"}
		if isRoot() {
			header = append(header, "PID", "CMD")
		}
		lines := [][]string{header}

		keys := make([]int, 0, len(listeners))
		for k := range listeners {
			keys = append(keys, k)
		}
		sort.Ints(keys)

		for _, port := range keys {
			processes := map[int]*ProcessInfo{}
			for _, listener := range listeners[port] {
				pid, ok := inodeToPid[listener.Inode]
				if !ok {
					pid = -1
				}

				process := processes[pid]
				if process == nil {
					process = &ProcessInfo{
						User:      username(listener.UID),
						Cmd:       processName(pid, extended),
						Addresses: []string{},
					}
					processes[pid] = process
				}
				process.Addresses = append(process.Addresses, listener.Address)
			}

			for pid, process := range processes {
				if (singlePort != 0 && port == singlePort) ||
					(singleUser != "" && process.User == singleUser) ||
					(singlePID != -1 && pid == singlePID) ||
					!(singlePort != 0 || singleUser != "" || singlePID != -1) {
					line := []string{fmt.Sprintf("%d", port), strings.Join(process.Addresses, ", "), process.User}
					if isRoot() {
						line = append(line, fmt.Sprintf("%d", pid), process.Cmd)
					}
					lines = append(lines, line)
					matchResult = 0
				}
			}
		}

		// print output
		if !quiet && len(lines) > 1 {
			if stanza > 0 {
				fmt.Println()
			}

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

			stanza++
		}
	}

	// exit success if any matches were found
	os.Exit(matchResult)
}
