all: build

build:

update:
	go get -u

test: update
	go test -v --cover
	
cover:
	go test -v --cover -coverprofile=cover.out
	go tool cover -html=cover.out -o cover.html
	rm cover.out

clean:
	rm -f go.sum cover.html
	git checkout go.mod
