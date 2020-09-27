# gnbsim
gnbsim is a 5G SA gNB/UE (Rel. 16) simulator for testing 5G System. The project is aimed to understand 5GC more efficiently than just reading 3GPP standard documents.

## Getting Started
<!--
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.
-->

### Prerequisites

* golang environment on linux host.
  - root previledge is required to set an IP address which is dynamically assigned by SMF.
  - GTP kernel module capability is required for using [go-gtp](https://github.com/wmnsk/go-gtp)
    - To check if GTP kernel module is present in your system, try the following command
      ```
      find /lib/modules/`uname -r` -name gtp.ko
      ```
      If you get someting like:
      ```
      /lib/modules/5.4.0-42-generic/kernel/drivers/net/gtp.ko
      ```
      it means that the module is present in your system. You may also want to try `modinfo gtp`.
      Otherwise, you need to install the GTP kernel module by following instructions here: https://osmocom.org/projects/openggsn/wiki/Kernel_GTP
    - If you would like to use 'Raspberry Pi' to run gnbsim, Kernel Compiling is required for activating GTP kernel module (gtp.ko).

* running free5gc somewhere.
  - subscriber has been registered by free5gc web console.
  - change 'ngapIPList' to external ip address in 'amfcfg.conf' 

### Installing and testing

* Download the related files.

```
$ git clone https://github.com/hhorai/gnbsim.git
$ cd gnbsim
```

* Build example binary.

```
$ make test		# test for each libary.
$ make			# building example binary.
```

* Edit the configuration file.
  - `imeisv` replace with the registered value of IMSI in free5gc web console (e.g. `208930000000003`)
  - `msin` replace with last 10 digits of the IMSI (e.g. `0000000003`)
  - `GTPuAddr` for the IP address of gnbsim
  - `GTPuIFname` for the network interface of gnbsim

```
$ cd example
$ vi example.json
```

* run 'example' with 'ip' option and specify the AMF IP address.

```
$ ./example -ip <AMF NGAP listen ip address set above>
```

* Then you can find the following line in the debug message. In this case, your configuration for free5gc and gnbsim are both correct.
```
***** Integrity check passed
```

* And you could also find your UE in 'subscriber' page of free5gc web console. In my environment, free5gc dashboard doesn't show my UE, but the actual transfered packet that is respond from web conole includes the information (PLMN and IMSI) of it in json format.

## Progress
* [done] Initial Registration
* [in progress] PDU Session Establishment
  - gnbsim can respond 'PDU Session Resource Setup Response' to AMF.
  - User plane functionalities are developed in progress.

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
