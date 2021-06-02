# gnbsim
gnbsim is a 5G SA gNB/UE (Rel. 16) simulator for testing 5G System. The project is aimed to understand 5GC more efficiently than just reading 3GPP standard documents.The original repostitory has been deleted. This repo is for backup purpose.

## Getting Started
<!--
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.
-->

### Prerequisites

* Golang environment on a Linux server to run gnbsim.
  - The project is tested on Raspbian GNU/Linux 10 (buster)

* free5gc is running somewhere.
  - [free5gc/free5gc](https://github.com/free5gc/free5gc) v3.0.5 is used for testing the project.
  - Tested subscriber(s) have been provisioned by the free5gc web console.
  - change the free5gc configurations.
    - free5gc/config/amfcfg.conf

      ```
      ngapIpList:
        - 192.168.1.17        # external IP address for N2 address.
        # - 127.0.0.1
      ```

    - free5gc/config/smfcfg.conf

      ```
      interfaces:
        - interfaceType:
          endpoints:
            - 192.168.1.18 # external IP address for GTP-U (N3) address.
            # - 127.0.0.8
      ```

    - free5gc/src/upf/build/config/upfcfg.yaml

      ```
      gtpu:
        - addr: 192.168.1.18  # external IP address for GTP-U (N3) address.
        # - addr: 127.0.0.8
      ```

### Installing and testing

* Download the related files.

  ```
  $ git clone https://github.com/AlohaLuo/gnbsim-backup.git
  $ cd gnbsim
  ```

* Build the example binary.
  ```
  $ make test		# (optional) unit test for each libary.
  $ make
  ```

* Edit the configuration file (example.json).
  - SUPI(IMSI) is formed by `mcc` + `mnc` + `msin`. (e.g. `208930123456789`)
  - `NGAPPeerAddr` indicates the IP address for N2 used by the AMF side.
  - `GTPuIFname` indicates the interface name for GTP-U used by gnbsim.
  - `GTPuLocalAddr` indicates the IP address for GTP-U used by gnbsim.
  - `url` indicates the destined URL for testing U-plane directly accessed by UEs.
  - [wiki page](https://github.com/hhorai/gnbsim/wiki) might be helpful to understand the environment.

  ```
  $ cd example
  $ vi example.json
  ```

* Run gnbsim
  - root privilege is required to set an IP address which is dynamically assigned by the SMF.

  ```
  $ sudo ./example
  ```

  - Then you can find the following line in the debug message. In this case, your configuration for `OPc` and `K` are both correct.

  ```
  ***** Integrity check passed
  ```

  - And you could also find your UEs in 'subscriber' page in the free5gc web console.

<!--
## Running the tests

Explain how to run the automated tests for this system

### Break down into end to end tests

Explain what these tests test and why

```
Give an example
```

### And coding style tests

Explain what these tests test and why

```
Give an example
```

## Deployment

Add additional notes about how to deploy this on a live system

## Built With

* [Dropwizard](http://www.dropwizard.io/1.0.2/docs/) - The web framework used
* [Maven](https://maven.apache.org/) - Dependency Management
* [ROME](https://rometools.github.io/rome/) - Used to generate RSS Feeds

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **Billie Thompson** - *Initial work* - [PurpleBooth](https://github.com/PurpleBooth)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details



## Acknowledgments

* [README-Template.md](https://gist.github.com/PurpleBooth/109311bb0361f32d87a2)

-->
