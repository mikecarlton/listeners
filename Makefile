# Makefile for building Go binary

listeners: listeners.go
	GO_ENABLED=0 go build -o listeners -ldflags "-w -s"

# Clean build cache and binary
clean:
	go clean
	rm -f listeners

# Cross-compile for different platforms
release: clean
	GOOS=linux GOARCH=amd64 go build -o listeners-linux-amd64 listeners.go
