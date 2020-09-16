all: build

build: update
	go build

update:
	go get -u

clean:
	rm -f example go.sum
	git checkout go.mod
