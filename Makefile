build: deps
	go build

deps:
	go get -u -v github.com/mediocregopher/lever

debug:
	go run main.go
