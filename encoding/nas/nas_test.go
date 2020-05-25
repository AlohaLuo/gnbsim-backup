package nas

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

var TestAuthenticationRequest string = "7e005600020000217d9192431b0560ca6c35a0212d6759e520109a4a995a657a800089c03b9ac78a0614"
var TestSecurityModeCommand string = "7e03ca400b02007e035d02000480a00000e1360100"
var TestRegistrationAccept string = "7e02823d94a5017e0242010177000b0202f839cafe000000000154070002f839000001150a040101020304011122335e010616012c"

func receive(ue *UE, msg string) {
	in, _ := hex.DecodeString(msg)
	ue.Decode(&in, len(in))
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
	ue.AuthParam.RESstar = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	v := ue.MakeAuthenticationResponse()
	//fmt.Printf("MakeRegistrationRequest: %02x\n", v)
	expect_str := "7e00572d10000102030405060708090a0b0c0d0e0f"
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("AuthenticationResponse\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestMakeRegistrationRequest(t *testing.T) {
	ue := NewNAS("nas_test.json")
	v := ue.MakeRegistrationRequest()
	//fmt.Printf("MakeRegistrationRequest: %02x\n", v)
	expect_str := "7e004179000d0102f8392143000010325476981001202e0480a00000"
	expect, _ := hex.DecodeString(expect_str)
	if reflect.DeepEqual(expect, v) == false {
		t.Errorf("RegistrationRequest\nexpect: %x\nactual: %x", expect, v)
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

	for _, p := range pattern {
		ue.recv.flag.imeisv = p.imeisv
		ue.recv.flag.rinmr = p.rinmr
		ue.wa.forceRINMR = p.forceRINMR
		v = ue.MakeSecurityModeComplete()
		fmt.Printf("MakeSecurityModeCoplete: %02x\n", v)

	}

	/*
		expect_str := "7e004179000d0102f8392143000010325476981001202e0480a00000"
		expect, _ := hex.DecodeString(expect_str)
		if reflect.DeepEqual(expect, v) == false {
			t.Errorf("RegistrationRequest\nexpect: %x\nactual: %x", expect, v)
		}
	*/
}

func TestDecode(t *testing.T) {
	ue := NewNAS("nas_test.json")

	pattern := []struct {
		in_str string
	}{
		{TestAuthenticationRequest},
		{TestSecurityModeCommand},
		{TestRegistrationAccept},
	}

	for _, p := range pattern {
		fmt.Printf("----------\n")
		receive(ue, p.in_str)
	}
}
