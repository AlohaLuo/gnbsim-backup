all: build

build:
	make -C example build

test:
	make -C encoding/per test
	make -C encoding/ngap test
	make -C encoding/nas test

cover:
	make -C encoding/per cover
	make -C encoding/ngap cover
	make -C encoding/nas cover

clean:
	make -C encoding/per clean
	make -C encoding/ngap clean
	make -C encoding/nas clean
	make -C example clean
