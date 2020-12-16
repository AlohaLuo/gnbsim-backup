all: build

build: update
	go build

update:
	go get -u

clean:
	rm -f gnbsim go.sum
	git checkout go.mod
