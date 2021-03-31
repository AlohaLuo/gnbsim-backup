# 1. Clone gnbsim #

```bash
git clone https://github.com/hhorai/gnbsim.git

cd gnbsim
```

# 2. Pre-requisite for docker

* Install docker package. At time of writing this tutorial : 

```bash
ubuntu@gnbsim:~/gnbsim/$ dpkg --list | grep docker
ii  docker-ce                                                   5:19.03.14~3-0~ubuntu-focal               amd64        Docker: the open-source application container engine
ii  docker-ce-cli                                               5:20.10.0~3-0~ubuntu-focal                amd64        Docker CLI: the open-source application container engine
```

* Install package docker-compose with version > 1.26. At time of writing this tutorial :
 
```bash
ubuntu@gnbsim:~/gnbsim/$ docker-compose version
docker-compose version 1.27.4, build 40524192
docker-py version: 4.3.1
CPython version: 3.7.7
OpenSSL version: OpenSSL 1.1.0l  10 Sep 2019
``` 
# 3. Build gnbsim docker image

* Docker build

```bash
ubuntu@gnbsim:~/gnbsim/$ docker build --target gnbsim --tag gnbsim:latest \ 
                                      --file docker/Dockerfile.ubuntu.18.04 .
```
* Clean intermediate containers 

```bash
docker image prune --force
```

# 4. Verify mount source for gtp kernel module in Docker-compose

* Note :- gnbsim requires gtp kernel module (by default present in linux kernel 4.7.0 onward) to be mounted inside docker container.
* Verify mount source for gtp kernel module by command <br/>
 `find /lib/modules/$(uname -r) -name gtp.ko`. <br/>
 Then update gtp kernel volume mount for service gnbsim in gnbsim/docker/scripts/docker-compose.yaml file.

# 5. Launch gnbsim docker service

```bash
ubuntu@gnbsim:~/gnbsim$ cd  docker/scripts/
ubuntu@gnbsim:~/gnbsim/docker/scripts$ docker-compose config --services
gnbsim
ubuntu@gnbsim:~/gnbsim/docker/scripts$ docker-compose up -d gnbsim
Creating gnbsim ... done
ubuntu@gnbsim:~/gnbsim/docker/scripts$ docker logs gnbsim --follow
Now setting these variables '@DNN@ @GNBID@ @GTPuIFname@ @GTPuLocalAddr@ @IMEISV@ @KEY@ @MCC@ @MNC@ @MSIN@ @NGAPPeerAddr@ @OPc@ @PagingDRX@ @ProtectionScheme@ @RANUENGAPID@ @RoutingIndicator@ @SD@ @SST@ @TAC@ @URL@'
Done setting the configuration
Running gnbsim

```
