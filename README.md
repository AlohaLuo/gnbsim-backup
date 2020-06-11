# gnbsim
gnbsim is a 5G SA gNB/UE simulator for testing 5GC system. The project is aimed to understand 5GC system more efficiently than just reading 3GPP standard documents.

## Getting Started
<!--
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.
-->

### Prerequisites

* golang environment on linux host.
  - gnbsim can complete 'Initial Registration'.
  - gnbsim cannot complete 'PDU Session Establishment' for now.
  - I will try to update my code step by step...
* running free5gc somewhere.
  - subscriber has been registered by free5gc web console.
  - change 'ngapIPList' to external ip address in 'amfcfg.conf' 

### Installing and testing

* Download the related files.

```shell
$ git clone https://github.com/hhorai/gnbsim.git
```

* Build example binary.

```shell
$ cd gnbsim/example
$ go build
```

* Edit the configuration file. In case of free5gc with default configuration, it might not be needed to edit, excluding 'msin' parameter.

```shell
$ vi example.json
```

* run 'example' with 'ip' option and specify the AMF ip address.

```shell
$ ./example -ip <AMF NGAP listen ip address set above>
```

* Then you can find the following line in the debug message. In this case, your configuration for free5gc and gnbsim are both correct.
```
***** Integrity check passed
```

* And you could also find your UE in 'subscriber' page of free5gc web console. In my environment, free5gc dashboard doesn't show my UE, but the actual transfered packet that is respond from web conole includes the information (PLMN and IMSI) of it in json format.

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
