all: build

build:
	make -C example build
	make -C cmd build

test:
	make -C encoding/gtp test
	make -C encoding/per test
	make -C encoding/nas test
	make -C encoding/ngap test

cover:
	make -C encoding/gtp cover
	make -C encoding/per cover
	make -C encoding/nas cover
	make -C encoding/ngap cover

clean:
	make -C encoding/gtp clean
	make -C encoding/per clean
	make -C encoding/nas clean
	make -C encoding/ngap clean
	make -C example clean
	make -C cmd clean
