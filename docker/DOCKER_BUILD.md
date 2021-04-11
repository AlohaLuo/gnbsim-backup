# 1. Clone gnbsim #

```bash
$ git clone https://github.com/hhorai/gnbsim.git

$ cd gnbsim
```

# 2. Pre-requisite for docker #

* Install docker package. At time of writing this tutorial : 

```bash
$ dpkg --list | grep docker
ii  docker-ce                                                   5:19.03.14~3-0~ubuntu-focal               amd64        Docker: the open-source application container engine
ii  docker-ce-cli                                               5:20.10.0~3-0~ubuntu-focal                amd64        Docker CLI: the open-source application container engine
```

* Install package docker-compose with version > 1.26. At time of writing this tutorial :
 
```bash
$ docker-compose version

docker-compose version 1.27.4, build 40524192
docker-py version: 4.3.1
CPython version: 3.7.7
OpenSSL version: OpenSSL 1.1.0l  10 Sep 2019
``` 
# 3. Build gnbsim docker image #

* Docker build

```bash
$ docker build --target gnbsim --tag gnbsim:latest --file docker/Dockerfile.ubuntu.20.04 .
```
* Clean intermediate containers 

```bash
$ docker image prune --force
```

# 4. Launch gnbsim docker service #
Update gnbsim config parameters in `docker/scripts/gnbsim.yaml` accordingly, before launching gnbsim docker service.

```bash
$ docker-compose -f docker/scripts/gnbsim.yaml config --services
gnbsim
```
```bash
$ docker-compose -f docker/scripts/gnbsim.yaml up -d gnbsim
Creating gnbsim ... done
```
```bash
$ docker logs gnbsim --follow
Now setting these variables '@DNN@ @GNBID@ @GTPuIFname@ @GTPuLocalAddr@ @IMEISV@ @KEY@ @MCC@ @MNC@ @MSIN@ @NGAPPeerAddr@ @OPc@ @PagingDRX@ @ProtectionScheme@ @RANUENGAPID@ @RoutingIndicator@ @SD@ @SST@ @TAC@ @URL@'
Done setting the configuration
Running gnbsim
```
