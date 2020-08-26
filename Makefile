all: build

build:
	make -C example build

test:
	make -C encoding/per test
	make -C encoding/ngap test
	make -C encoding/nas test
