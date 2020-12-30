package nas

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

// send
var TestRegistrationRequest string = "7e004179000d0102f8392143000010325476981001202e0480a00000"
var TestAuthenticationResponse string = "7e00572d10803adcacc364fc000bdc0f65e324eaa1"
var TestSecurityModeComplete []string = []string{
	"7e04da52b828007e005e",
	"7e042e7d15af017e005e7700090500000001000001f1",
	"7e042bcd6bc3027e005e7700090500000001000001f171001c7e004179000d0102f8392143000010325476981001202e0480a00000",
	"7e04a314ad62037e005e7700090500000001000001f171001c7e004179000d0102f8392143000010325476981001202e0480a00000",
}
var TestRegistrationComplete string = "7e04006d1298007e0043"
var TestPDUSessionEstablishmentRequest string = "7e0208d593cc007e00670100072e0101c1ffff93120181220401010203250908696e7465726e6574"
var TestDeregistrationRequest string = "7e04d733af71007e004571000bf202f839cafe0000000001"

// receive
var TestAuthenticationRequest string = "7e00560002000021fc64081953bb33c0682edf1690b25821201094bbaf40940a8000c6a72c4efbaf0337"
var TestSecurityModeCommand string = "7e03937711bc007e035d02000480a00000e1360100"
var TestRegistrationAccept string = "7e02930d75cf017e0242010177000b0202f839cafe000000000154070002f839000001150a040101020304011122335e010616012c"
var TestPDUSessionEstablishmentAccept string = "7e0222994e9f027e00680100202e0100c21100090100063131010100000601e80301e80359322905013c3c00011201"
var TestDeregistrationAccept string = "7e0046"

func receive(ue *UE, msg string) {
	in, _ := hex.DecodeString(msg)
	ue.Decode(&in)
	fmt.Printf("")
}

func TestStr2BCD(t *testing.T) {
	bcd := Str2BCD("12345")
	expect := []byte{0x21, 0x43, 0x05}
	if reflect.DeepEqual(expect, bcd) == false {
		t.Errorf("value expect: 0x%02x, actual 0x%02x", expect, bcd)
	}

	bcd = Str2BCD("12345f")
	expect = []byte{0x21, 0x43, 0xf5}
	if reflect.DeepEqual(expect, bcd) == false {
		t.Errorf("value expect: 0x%02x, actual 0x%02x", expect, bcd)
	}
}

func TestMakeAuthenticationResponse(t *testing.T) {
	ue := NewNAS("nas_test.json")

	receive(ue, TestAuthenticationRequest)
	v := ue.MakeAuthenticationResponse()
	expect_str := TestAuthenticationResponse
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("Authentication Response\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestMakeRegistrationRequest(t *testing.T) {
	ue := NewNAS("nas_test.json")
	v := ue.MakeRegistrationRequest()
	//fmt.Printf("MakeRegistrationRequest: %02x\n", v)
	expect_str := TestRegistrationRequest
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("Registration Request\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestMakeRegistrationComplete(t *testing.T) {

	ue := NewNAS("nas_test.json")
	v := []byte{}

	receive(ue, TestAuthenticationRequest)
	receive(ue, TestSecurityModeCommand)
	receive(ue, TestRegistrationAccept)

	v = ue.MakeRegistrationComplete()
	expect_str := TestRegistrationComplete
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("Registration Complete\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestMakeSecurityModeComplete(t *testing.T) {

	pattern := []struct {
		imeisv     bool
		rinmr      bool
		forceRINMR bool
	}{
		{false, false, false},
		{true, false, false},
		{true, true, false},
		{true, false, true},
	}

	ue := NewNAS("nas_test.json")
	v := []byte{}

	receive(ue, TestAuthenticationRequest)
	receive(ue, TestSecurityModeCommand)

	for i, p := range pattern {
		ue.Recv.flag.imeisv = p.imeisv
		ue.Recv.flag.rinmr = p.rinmr
		ue.wa.forceRINMR = p.forceRINMR
		v = ue.MakeSecurityModeComplete()
		expect_str := TestSecurityModeComplete[i]
		expect, _ := hex.DecodeString(expect_str)
		if reflect.DeepEqual(expect, v) == false {
			t.Errorf("Security Mode Complete[%d]\nexpect: %x\nactual: %x", i, expect, v)
		}

	}
}

func TestMakePDUSessionEstablishmentRequest(t *testing.T) {

	ue := NewNAS("nas_test.json")

	receive(ue, TestAuthenticationRequest)
	receive(ue, TestSecurityModeCommand)
	receive(ue, TestRegistrationAccept)

	v := ue.MakePDUSessionEstablishmentRequest()
	expect_str := TestPDUSessionEstablishmentRequest
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("PDU Session Establishemnt Request\nexpect: %x\nactual: %x", expect, v)
	}

}

func TestMakeDeregistrationRequest(t *testing.T) {
	ue := NewNAS("nas_test.json")

	receive(ue, TestAuthenticationRequest)
	receive(ue, TestSecurityModeCommand)
	receive(ue, TestRegistrationAccept)
	receive(ue, TestPDUSessionEstablishmentAccept)

	v := ue.MakeDeregistrationRequest()
	//fmt.Printf("MakeRegistrationRequest: %02x\n", v)
	expect_str := TestDeregistrationRequest
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("Deregistration Request\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestDecode(t *testing.T) {
	ue := NewNAS("nas_test.json")
	ue.dbgLevel = 1
	fmt.Printf("URL = %s\n", ue.URL)

	pattern := []struct {
		in_str string
		desc   string
	}{
		{TestAuthenticationRequest,
			"Authentication Request"},
		{TestSecurityModeCommand,
			"Security Mode Command"},
		{TestRegistrationAccept,
			"Registration Accept"},
		{TestPDUSessionEstablishmentAccept,
			"PDU Session Establishemtn Accept"},
		{TestDeregistrationAccept,
			"Deregistration Accept"},
	}

	for _, p := range pattern {
		fmt.Printf("---------- test decode: %s\n", p.desc)
		receive(ue, p.in_str)
		if ue.DecodeError != nil {
			t.Errorf("%s: %v", p.desc, ue.DecodeError)
		}
	}
}
