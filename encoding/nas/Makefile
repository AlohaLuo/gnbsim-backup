all: build

build:

test:
	go test -v --cover
	
cover:
	go test -v --cover -coverprofile=cover.out
	go tool cover -html=cover.out -o cover.html
