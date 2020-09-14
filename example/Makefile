all: build

build: update
	go build

update:
	go get -u

clean:
	rm -f example
	git checkout go.mod
