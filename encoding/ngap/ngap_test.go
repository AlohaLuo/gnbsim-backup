package ngap

import (
	"fmt"
	"testing"
)

func compareSlice(actual, expect []byte) bool {
	if len(actual) != len(expect) {
		return false
	}
	for i := 0; i < len(actual); i++ {
		if actual[i] != expect[i] {
			return false
		}
	}
	fmt.Printf("")
	return true
}

/*
//func encGlobalRANNodeID() (v []byte, err error) {
func TestMakeGlobalRANNodeID(t *testing.T) {
	v, _ := encGlobalRANNodeID()
	fmt.Printf("v = 0x%02x\n", v)
}

//func encSliceSupportList() (v []byte, bitlen int) {
func TestMakeSliceSupportList(t *testing.T) {
	v := encSliceSupportList()
	fmt.Printf("v = 0x%02x\n", v)
}

func TestMakePLMNIdentity(t *testing.T) {

	expect := make([]byte, 3, 3)
	expect[0] = 0x21
	expect[1] = 0xf3
	expect[2] = 0x54
	actual := encPLMNIdentity(123, 45)
	if compareSlice(actual, expect) == false {
		t.Errorf("expect: 0x%02x, actual 0x%02x", expect, actual)
	}
}

func TestMakeNGSetupRequest(t *testing.T) {
	MakeNGSetupRequest()
}

func TestMakeGlobalRANNodeID(t *testing.T) {
	encGlobalRANNodeID(123, 45)
}
*/

/*
func TestInitNGAP(t *testing.T) {
	_ = InitNGAP("../nofile.json")
}
*/

func TestMakeNGSetupRequest(t *testing.T) {
	gnbp := NewNGAP("gnb.json")
	fmt.Printf("gnbp: %p\n", gnbp)
	fmt.Printf("gnbp: %+v\n", *gnbp)
	v := gnbp.MakeNGSetupRequest()
	fmt.Printf("ngsetup = %02x\n", v)
}
