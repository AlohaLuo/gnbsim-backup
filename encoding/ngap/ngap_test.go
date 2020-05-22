package ngap

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

var TestAuthenticationRequest string = "0004403e000003000a000200010055000200000026002b2a7e005600020000217d9192431b0560ca6c35a0212d6759e520109a4a995a657a800089c03b9ac78a0614"
var TestSecurityModeCommand string = "00044029000003000a0002000100550002000000260016157e03ca400b02007e035d02000480a00000e1360100"

func receive(gnb *GNB, msg string) {
	in, _ := hex.DecodeString(msg)
	gnb.Decode(&in)
	fmt.Printf("")
}

func TestMakeInitialUEMessage(t *testing.T) {
	gnbp := NewNGAP("ngap_test.json")
	v := gnbp.MakeInitialUEMessage()
	expect_str := "000f40470000040055000200000026001d1c7e004179000d0102f8392143000010325476981001202e0480a000000079000f4002f839000004001002f839000102005a4001180070400100"
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("InitialUEMessage\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestMakeUplinkNASTransport(t *testing.T) {
	gnb := NewNGAP("ngap_test.json")
	gnb.UE.PowerON()

	gnb.recv.AMFUENGAPID = []byte{0x00, 0x01}
	//gnb.UE.AuthParam.RESstar = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	receive(gnb, TestAuthenticationRequest)
	v := gnb.MakeUplinkNASTransport()
	expect_str := "002e403c000004000a0002000100550002000000260016157e00572d109757ce0fbec35af1c525385ea11d4d260079000f4002f839000004001002f839000102"
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("UplinkNASTransport\nexpect: %x\nactual: %x", expect, v)
	}

	receive(gnb, TestSecurityModeCommand)
	v = gnb.MakeUplinkNASTransport()
	fmt.Printf("UplinkNASTransport\nexpect: \nactual: %x\n", v)
	/*
		expect_str := "002e403c000004000a0002000100550002000000260016157e00572d109757ce0fbec35af1c525385ea11d4d260079000f4002f839000004001002f839000102"
		expect, _ := hex.DecodeString(expect_str)
		if reflect.DeepEqual(expect, v) == false {
			t.Errorf("UplinkNASTransport\nexpect: %x\nactual: %x", expect, v)
		}
	*/
}

func TestMakeNGSetupRequest(t *testing.T) {
	gnbp := NewNGAP("ngap_test.json")
	v := gnbp.MakeNGSetupRequest()
	expect_str := "00150028000003001b00080002f839000000040066001000000001020002f839000010081234560015400100"
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("NGSetupRequest\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestDecode(t *testing.T) {

	pattern := []struct {
		in_str string
	}{
		{TestAuthenticationRequest},
		{TestSecurityModeCommand},
	}

	gnb := NewNGAP("ngap_test.json")

	for _, p := range pattern {
		fmt.Printf("----------\n")
		receive(gnb, p.in_str)
	}
}
