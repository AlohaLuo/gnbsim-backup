package ngap

import (
	"encoding/hex"
	"fmt"
	"log"
	"reflect"
	"testing"

	"github.com/hhorai/gnbsim/encoding/nas"
)

// send message
var TestNGSetupRequest string = "00150028000003001b00080002f839000000040066001000000000010002f839000010080102030015400100"
var TestInitialUEMessage string = "000f40470000050055000200000026001d1c7e004179000d0102f8392143000010325476981001202e0480a000000079000f4002f839000004001002f839000001005a4001180070400100"
var TestULAuthenticationResponse string = "002e403c000004000a0002000100550002000000260016157e00572d10803adcacc364fc000bdc0f65e324eaa10079400f4002f839000004001002f839000001"
var TestULSecurityModeComplete string = "002e403d000004000a0002000100550002000000260017167e0452a73e0c007e005e7700090500000001000001f10079400f4002f839000004001002f839000001"
var TestInitialContextSetupResponse string = "200e000f000002000a00020001005500020000"
var TestULRegistrationComplete string = "002e4031000004000a000200010055000200000026000b0a7e042cbd08cf017e00430079400f4002f839000004001002f839000001"
var TestPDUSessionResourceSetupResponse string = "201d0024000003000a00020001005500020000004b40110000010d0003e0c0a80103000003e70001"

// receive message
var TestNGSetupResponse string = "20150031000004000100050100414d4600600008000002f839cafe0000564001ff005000100002f839000110080102031008112233"
var TestDLAuthenticationRequest string = "0004403e000003000a000200010055000200000026002b2a7e00560002000021fc64081953bb33c0682edf1690b25821201094bbaf40940a8000c6a72c4efbaf0337"
var TestDLSecurityModeCommand string = "00044029000003000a0002000100550002000000260016157e036c2b24e2007e005d02000480a00000e1360100"
var TestInitialContextSetupRequest string = "000e0080a7000009000a00020001005500020000001c00070002f839cafe000000000a2201010203100811223300770009000004000000000000005e002013663ab7286c9a6af7cba0b1fd9e6ed48045d4356d46ff3944c81c63324fd803002440040002f839002240080000000100ffff0100264036357e02930d75cf017e0242010177000b0202f839cafe000000000154070002f839000001150a040101020304011122335e010616012c"
var TestInitialContextSetupRequest2 string = "000e0080f500000b000a00020001005500020000006e0008080f4240200f4240001c00070002f839cafe000047002a000001402001020321000003008b000a01f07f00000800000001008600010000880007000000000938000000000a2201010203100811223300770009000000100000000000005e0020473007e30d4d0d77a7073e5b43b909562b7a8c461fc7ef0b73ab4026edbb91aa002440040002f839002240080000000100ffff010026404a497e02809e40eb027e006801003a2e0101c211000901000631310101ff00060103e80103e859322905013c3c0001220401010203790006002041010109250908696e7465726e65741201"
var TestDLPDUSessionEstablishmentAccept string = "001d006d000003000a00020001005500020000004a005a0040012f7e0222994e9f027e00680100202e0100c21100090100063131010100000601e80301e80359322905013c3c00011201402001020321000003008b000a01f0c0a801120000000100860001000088000700010000093800"

var TestOpen5gsNGSetupResponse string = "201500320000040001000e05806f70656e3567732d616d663000600008000002f83901004000564001ff005000080002f83900000008"
var TestOpen5gsDLAuthenticationRequest string = "0004403e000003000a000200020055000200000026002b2a7e00560002000021d231c4098df35d5ea33e62ffad05d2fa2010aaf6a4fd4c3b800059dc4597900d4b1f"
var TestOpen5gsDLSecurityModeCommand string = "00044027000003000a0002000200550002000000260014137e03fd70f3b3007e005d02000280a0e1360102"
var TestOpen5gsInitialContextSetupRequest string = "000e00809e000009000a00020002005500020000006e000a0c3e800000303e800000001c00070002f83901004000000002000100770009000004000000000000005e002050437b88f28f5f228eebd3e4517265f99473dbc12b7475a56da62e755d60166e002240080000000100ffff010026402f2e7e0227d3fd9f017e0042010177000bf202f839010040c800cbd954072002f83900000115020101210201005e0129"
var TestOpen5gsConfigurationUpdateCommand string = "0004403a000003000a0002000200550002000000260027267e024745e85a027e0054430f10004f00700065006e0035004700534702010151114500490100"
var TestOpen5gsDLPDUSessionEstablishmentAccept string = "001d00808f000003000a00020002005500020000004a007c004001467e02f1620a15037e00680100372e0101c211000901000631210101ff01060a00030a000359322905010a2e0002220101790006012041010109250908696e7465726e6574120100202f0000040082000a0c3e800000303e800000008b000a01f0c0a8c7ca0000000100860001000088000700010000091c00"

func initEnv() (gnb *GNB, ue *nas.UE) {

	RanUeNgapId = 0

	gnb = NewNGAP("ngap_test.json")
	tmp := gnb.UE
	ue = &tmp
	ue.PowerON()
	gnb.CampIn(ue)

	return
}

func recvfromNW(gnb *GNB, msg string) {
	in, _ := hex.DecodeString(msg)
	gnb.Decode(&in)
	fmt.Printf("")
}

func TestMakePDUSessionResourceSetupResponse(t *testing.T) {
	log.SetPrefix("[NGAP TEST]")

	pattern := []struct {
		in_str string
	}{
		{TestNGSetupResponse},
		{TestDLAuthenticationRequest},
		{TestDLSecurityModeCommand},
		{TestInitialContextSetupRequest},
		{TestDLPDUSessionEstablishmentAccept},
	}

	gnb, ue := initEnv()

	for _, p := range pattern {
		recvfromNW(gnb, p.in_str)
	}

	gnb.SetDebugLevel(1)
	ue.SetDebugLevel(1)
	v := gnb.MakePDUSessionResourceSetupResponse(ue)
	expect_str := TestPDUSessionResourceSetupResponse
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		//fmt.Printf("PDUSessionResourceSetupResponse test not implemented yet.\n")
		t.Errorf("PDUSessionResourceSetupResponse\nexpect: %x\nactual: %x", expect, v)
	}

}

func TestInitialContestSetupResponse(t *testing.T) {

	gnb, ue := initEnv()

	recvfromNW(gnb, TestDLAuthenticationRequest)
	v := gnb.MakeInitialContextSetupResponse(ue)
	expect_str := TestInitialContextSetupResponse
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("InitialContextSetupResponse\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestMakeInitialUEMessage(t *testing.T) {

	gnb, ue := initEnv()

	pdu := ue.MakeRegistrationRequest()
	gnb.RecvfromUE(ue, &pdu)
	v := gnb.MakeInitialUEMessage(ue)
	expect_str := TestInitialUEMessage
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("InitialUEMessage\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestMakeUplinkNASTransport(t *testing.T) {

	gnb, ue := initEnv()

	var expect_str string
	var expect []byte

	recvfromNW(gnb, TestDLAuthenticationRequest)
	pdu := ue.MakeAuthenticationResponse()
	gnb.RecvfromUE(ue, &pdu)

	v := gnb.MakeUplinkNASTransport(ue)
	expect_str = TestULAuthenticationResponse
	expect, _ = hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("UplinkNASTransport1\nexpect: %x\nactual: %x", expect, v)
	}

	recvfromNW(gnb, TestDLSecurityModeCommand)
	pdu = ue.MakeSecurityModeComplete()
	gnb.RecvfromUE(ue, &pdu)

	v = gnb.MakeUplinkNASTransport(ue)
	expect_str = TestULSecurityModeComplete
	expect, _ = hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("UplinkNASTransport2\nexpect: %x\nactual: %x", expect, v)
	}

	recvfromNW(gnb, TestInitialContextSetupRequest)
	pdu = ue.MakeRegistrationComplete()
	gnb.RecvfromUE(ue, &pdu)

	v = gnb.MakeUplinkNASTransport(ue)
	expect_str = TestULRegistrationComplete
	expect, _ = hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("UplinkNASTransport3\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestMakeNGSetupRequest(t *testing.T) {

	gnb, _ := initEnv()

	v := gnb.MakeNGSetupRequest()
	expect_str := TestNGSetupRequest
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("NGSetupRequest\nexpect: %x\nactual: %x", expect, v)
	}

	expect_ip := "192.168.1.17"
	if gnb.NGAPPeerAddr != "192.168.1.17" {
		t.Errorf("NGSetupRequest\nexpect: %s\nactual: %s",
			expect_ip, gnb.NGAPPeerAddr)
	}
	//fmt.Printf("NGAP Peer Addr: %s", gnb.NGAPPeerAddr)
}

func TestDecode(t *testing.T) {

	pattern := []struct {
		in_str string
		desc   string
	}{
		{TestNGSetupResponse,
			"free5gc: NG Setup Response"},
		{TestDLAuthenticationRequest,
			"free5gc: DL Authentication Request"},
		{TestDLSecurityModeCommand,
			"free5gc: DL Security Mode Command"},
		{TestInitialContextSetupRequest,
			"free5gc: Initial Context Setup Request"},
		{TestInitialContextSetupRequest2,
			"free5gc: Initial Context Setup Request #2"},
		{TestDLPDUSessionEstablishmentAccept,
			"free5gc: PDU Session Establishment Accept"},
	}

	pattern2 := []struct {
		in_str string
		desc   string
	}{
		{TestOpen5gsNGSetupResponse,
			"open5gs: NG Setup Response"},
		{TestOpen5gsDLAuthenticationRequest,
			"open5gs: DL Authentication Request"},
		{TestOpen5gsDLSecurityModeCommand,
			"open5gs: DL Security Mode Command"},
		{TestOpen5gsInitialContextSetupRequest,
			"open5gs: Initial Context Setup Request"},
		{TestOpen5gsConfigurationUpdateCommand,
			"open5gs: Configuration Update Command"},
		{TestOpen5gsDLPDUSessionEstablishmentAccept,
			"open5gs: PDU Session Establishment Accept"},
	}

	gnb, ue := initEnv()

	for _, p := range pattern {
		fmt.Printf("---------- test decode: %s\n", p.desc)

		gnb.SetDebugLevel(1)
		ue.SetDebugLevel(1)
		recvfromNW(gnb, p.in_str)

		if gnb.DecodeError != nil {
			t.Errorf("%s: %v", p.desc, gnb.DecodeError)
		}
	}

	gnb, ue = initEnv()

	for _, p := range pattern2 {
		fmt.Printf("---------- test decode: %s\n", p.desc)

		gnb.SetDebugLevel(1)
		ue.SetDebugLevel(1)
		recvfromNW(gnb, p.in_str)

		if gnb.DecodeError != nil {
			t.Errorf("%s: %v", p.desc, gnb.DecodeError)
		}
	}
}
