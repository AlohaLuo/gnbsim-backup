// Copyright 2019-2020 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

// Package nas is implementation for non-access stratum (NAS) procedure
// in the 5GS Sytem.
// document version: 3GPP TS 24.501 v16.3.0 (2019-12)
package nas

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
)

type UE struct {
	MSIN             string
	MCC              uint8
	MNC              uint8
	RoutingIndicator uint16
	ProtectionScheme string
}

// 9.1.1 NAS message format
type NasMessageMM struct {
	ExtendedProtocolDiscriminator uint8
	SecurityHeaderType            uint8
	MessageType                   uint8
}

// 8.2.6 Registration request
type RegistrationRequest struct {
	head                     NasMessageMM
	registrationTypeAndngKSI uint8
	fiveGSMobileID           FiveGSMobileID
}

// TS 24.007 11.2.3.1.1A Extended protocol discriminator (EPD)
const (
	EPD5GSSessionManagement  = 0x2e
	EPD5GSMobilityManagement = 0x7e
)

/*
type NasMessageSM struct {
	ExtendedProtocolDiscriminator uint8
	PDUSessionID uint8
	ProcedureTransactionID uint8
	MessageType uint8
}
*/

// 9.3 Security header type
const (
	SecurityHeaderTypePlain = iota
	SecurityHeaderTypeIntegrityProtected
	SecurityHeaderTypeIntegrityProtectedAndCiphered
)

// 9.7 Message type
const (
	MessageTypeRegistrationRequest = 0x41
)

// 9.11.3.4 5GS mobile identity
type FiveGSMobileID struct {
	length                 uint16
	supiFormatAndTypeID    uint8
	plmn                   [3]uint8
	routingIndicator       [2]uint8
	protectionScheme       uint8
	homeNetworkPublicKeyID uint8
	schemeOutput           [5]uint8
}

const (
	TypeIDNoIdentity = iota
	TypeIDSUCI
)

const (
	SUPIFormatIMSI = iota
	SUPIFormatNetworkSpecificID
)

const (
	ProtectionSchemeNull = iota
	ProtectionSchemeProfileA
	ProtectionSchemeProfileB
)

// 9.11.3.7 5GS registration type
const (
	RegistrationTypeInitialRegistration        = 0x01
	RegistrationTypeFlagFollowOnRequestPending = 0x08
)

// 9.11.3.32 NAS key set identifier
const (
	KeySetIdentityNoKeyIsAvailable          = 0x07
	KeySetIdentityFlagMappedSecurityContext = 0x08
)

// 9.11.3.54 UE security capability
type UESecurityCapability struct {
	iei    uint8
	length uint8
	ea     uint8
	ia     uint8
	eea    uint8
	eia    uint8
}

const (
	EA0 = 0x80
	EA1 = 0x40
	EA2 = 0x20
	IA0 = 0x80
	IA1 = 0x40
	IA2 = 0x20
)

func Str2BCD(str string) (bcd []byte) {

	byteArray := []byte(str)
	bcdlen := len(byteArray) / 2
	if len(byteArray)%2 == 1 {
		bcdlen++
	}
	bcd = make([]byte, bcdlen, bcdlen)

	for i, v := range byteArray {

		n, _ := strconv.ParseUint(string(v), 16, 8)
		j := i / 2

		if i%2 == 0 {
			bcd[j] = byte(n)
		} else {
			bcd[j] |= (byte(n) << 4)
		}
	}

	return
}

func NewNAS(filename string) (p *UE) {

	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	var ue UE
	p = &ue
	json.Unmarshal(bytes, p)

	return
}

// 8.2.6 Registration request
// 5.5.1.2 Registration procedure for initial registration
func (p *UE) MakeRegistrationRequest() (pdu []byte) {

	var req RegistrationRequest
	var h *NasMessageMM = &req.head
	h.ExtendedProtocolDiscriminator = EPD5GSMobilityManagement
	h.SecurityHeaderType = SecurityHeaderTypePlain
	h.MessageType = MessageTypeRegistrationRequest

	var regType uint8 = RegistrationTypeInitialRegistration |
		RegistrationTypeFlagFollowOnRequestPending
	var ngKSI uint8 = KeySetIdentityNoKeyIsAvailable

	req.registrationTypeAndngKSI = regType | (ngKSI << 4)

	var f *FiveGSMobileID = &req.fiveGSMobileID
	var typeID uint8 = TypeIDSUCI
	var supiFormat uint8 = SUPIFormatIMSI

	/*
	 * it doesn't work with "f.length = uint16(unsafe.Sizeof(*f) - 2)"
	 * because of the octet alignment.
	 */
	f.length = 13
	f.supiFormatAndTypeID = typeID | (supiFormat << 4)
	f.plmn = encPLMN(p.MCC, p.MNC)
	f.routingIndicator = encRoutingIndicator(p.RoutingIndicator)
	f.protectionScheme = encProtectionScheme(p.ProtectionScheme)
	f.homeNetworkPublicKeyID = 0
	f.schemeOutput = encSchemeOutput(p.MSIN)

	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, req)
	binary.Write(data, binary.BigEndian, encUESecurityCapability())
	pdu = data.Bytes()

	return
}

func encPLMN(mcc, mnc uint8) (plmn [3]byte) {
	format := "%d%d"
	if mnc < 100 {
		format = "%df%d"
	}

	str := fmt.Sprintf(format, mcc, mnc)
	for i, v := range Str2BCD(str) {
		plmn[i] = v
	}
	return
}

func encRoutingIndicator(ind uint16) (ri [2]byte) {
	str := fmt.Sprintf("%d", ind)
	for i, v := range Str2BCD(str) {
		ri[i] = v
	}
	return
}

func encProtectionScheme(profile string) (p uint8) {
	switch profile {
	case "null":
		p = ProtectionSchemeNull
	}
	return
}

func encSchemeOutput(msin string) (so [5]byte) {
	for i, v := range Str2BCD(msin) {
		so[i] = v
	}
	return
}

// 9.11.3.54 UE security capability
func encUESecurityCapability() (sc UESecurityCapability) {
	sc.iei = 0x2e
	sc.length = 4
	sc.ea = EA0 | EA2
	sc.ia = IA0 | IA2

	return
}
