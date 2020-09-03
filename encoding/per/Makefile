all: build

build: update

update:

test: update
	go test -v --cover

cover: update
	go test -v --cover -coverprofile=cover.out
	go tool cover -html=cover.out -o cover.html
	rm cover.out

clean:
	rm -f cover.html
