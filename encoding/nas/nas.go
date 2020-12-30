// Copyright 2019-2020 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

// Package nas is implementation for non-access stratum (NAS) procedure
// in the 5GS Sytem.
// document version: 3GPP TS 24.501 v16.3.0 (2019-12)
package nas

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"reflect"
	"strconv"
	"strings"

	"github.com/aead/cmac"
	"github.com/wmnsk/milenage"
)

type UE struct {
	MSIN             string
	MCC              int
	MNC              int
	IMEISV           string
	RoutingIndicator uint16
	ProtectionScheme string
	AuthParam        AuthParam
	SNSSAI           SNSSAI
	DNN              string
	URL              string

	state5GMM int
	state5GSM int

	sm struct {
		pduSessionId           uint8
		procedureTransactionId uint8
	}

	Recv struct {
		flag struct {
			imeisv bool
			rinmr  bool
		}
		state        int
		fiveGGUTI    []byte
		tai          []TAI
		allowedNSSAI []SNSSAI
		t3502        int
		t3512        int
		PDUAddress   net.IP
	}

	NasCount uint32

	wa struct {
		securityHeaderParsed bool
		forceRINMR           bool
	}

	dbgLevel int
	indent   int // indent for debug print.

	DecodeError error
}

// 5.1.3 5GMM sublayer states
// actual value is not defined in the standard.
const (
	//fiveGMMNULL = iota
	state5GMMDeregistared = iota
	state5GMMRegisteredInitiated
	state5GMMRegistered
	state5GMMServiceRequestInitiated
	state5GMMDeregistaredInitiated
)

var state5GMMstr = map[int]string{
	//state5GMMNULL:                    "5GMM-NULL",
	state5GMMDeregistared:            "5GMM-DEREGISTERED",
	state5GMMRegisteredInitiated:     "5GMM-REGISTERED-INITIATED",
	state5GMMRegistered:              "5GMM-REGISTERED",
	state5GMMServiceRequestInitiated: "5GMM-SERVICE-REQUEST-INITIATED",
	state5GMMDeregistaredInitiated:   "5GMM-DEREGISTERED-INITIATED",
}

// my receive flag definition
const (
	rcvdNull = iota
	rcvdAuthenticationRequest
	rcvdSecurityModeCommand
	rcvdRegistrationAccept
)

var rcvdStateStr = map[int]string{
	rcvdNull:                  "NULL",
	rcvdAuthenticationRequest: "Received Authentication Request",
	rcvdSecurityModeCommand:   "Received Security Mode Command",
	rcvdRegistrationAccept:    "Received Registration Accept",
}

// TS 24.007 11.2.3.1.1A Extended protocol discriminator (EPD)
const (
	EPD5GSSessionManagement  = 0x2e
	EPD5GSMobilityManagement = 0x7e
)

var epdStr = map[byte]string{
	EPD5GSSessionManagement:  "5G Session Management",
	EPD5GSMobilityManagement: "5G Mobility Management",
}

// 9.3 Security header type
const (
	SecurityHeaderTypePlain = iota
	SecurityHeaderTypeIntegrityProtected
	SecurityHeaderTypeIntegrityProtectedAndCiphered
	SecurityHeaderTypeIntegrityProtectedWithNewContext
	SecurityHeaderTypeIntegrityProtectedAndCipheredWithNewContext
)

// 9.7 Message type
const (
	MessageTypeRegistrationRequest            = 0x41
	MessageTypeRegistrationAccept             = 0x42
	MessageTypeRegistrationComplete           = 0x43
	MessageTypeDeregistrationRequest          = 0x45
	MessageTypeDeregistrationAccept           = 0x46
	MessageTypeAuthenticationRequest          = 0x56
	MessageTypeAuthenticationResponse         = 0x57
	MessageTypeSecurityModeCommand            = 0x5d
	MessageTypeSecurityModeComplete           = 0x5e
	MessageTypeULNasTransport                 = 0x67
	MessageTypeDLNasTransport                 = 0x68
	MessageTypePDUSessionEstablishmentRequest = 0xc1
	MessageTypePDUSessionEstablishmentAccept  = 0xc2
)

var msgTypeStr = map[int]string{
	MessageTypeRegistrationRequest:            "Registration Request",
	MessageTypeRegistrationAccept:             "Registration Accept",
	MessageTypeRegistrationComplete:           "Registration Complete",
	MessageTypeDeregistrationRequest:          "Deregistration Request",
	MessageTypeDeregistrationAccept:           "Deregistration Accept",
	MessageTypeAuthenticationRequest:          "Authentication Request",
	MessageTypeAuthenticationResponse:         "Authentication Response",
	MessageTypeSecurityModeCommand:            "Security Mode Command",
	MessageTypeSecurityModeComplete:           "Security Mode Complete",
	MessageTypeULNasTransport:                 "UL NAS Transport",
	MessageTypeDLNasTransport:                 "DL NAS Transport",
	MessageTypePDUSessionEstablishmentRequest: "PDU Session Establishment Request",
	MessageTypePDUSessionEstablishmentAccept:  "PDU Session Establishment Accept",
}

const (
	ieiRequestType          = 0x8
	ieiPDUSessionType       = 0x9
	ieiIMEISVRequest        = 0xe
	iei5GMMCapability       = 0x10
	ieiPDUSessionID2        = 0x12
	ieiNSSAI                = 0x15
	ieiGPRSTimer2           = 0x16
	ieiAuthParamAUTN        = 0x20
	ieiAuthParamRAND        = 0x21
	ieiSNSSAI               = 0x22
	ieiDNN                  = 0x25
	ieiPDUAddress           = 0x29
	ieiAuthParamRES         = 0x2d
	ieiUESecurityCapability = 0x2e
	ieiAdditional5GSecInfo  = 0x36
	ieiTAIList              = 0x54
	iei5GSMCause            = 0x59
	ieiGPRSTimer3           = 0x5e
	ieiNASMessageContainer  = 0x71
	iei5GSMobileIdentity    = 0x77
	ieiNonSupported         = 0xff
)

var ieStr = map[int]string{
	ieiRequestType:          "Request Type",
	ieiPDUSessionType:       "PDU Session Type",
	ieiIMEISVRequest:        "IMEISV Request",
	iei5GMMCapability:       "5G MM Capability",
	ieiPDUSessionID2:        "PDU session identity 2",
	ieiNSSAI:                "NSSAI",
	ieiGPRSTimer2:           "GPRS Timer 2",
	ieiAuthParamAUTN:        "Authentication Parameter AUTN",
	ieiAuthParamRAND:        "Authentication Parameter RAND",
	ieiSNSSAI:               "S-NSSAI",
	ieiDNN:                  "DNN",
	ieiPDUAddress:           "PDU address",
	ieiAuthParamRES:         "Authentication response parameter",
	ieiUESecurityCapability: "UE Security Capability",
	ieiAdditional5GSecInfo:  "Additional 5G Security Information",
	ieiTAIList:              "Tracking Area Identity List",
	iei5GSMCause:            "5GSM cause",
	ieiGPRSTimer3:           "GPRS Timer 3",
	ieiNASMessageContainer:  "NAS Message Container",
	iei5GSMobileIdentity:    "5GS Mobile Identity",
	ieiNonSupported:         "Non Supported",
}

func NewNAS(filename string) (ue *UE) {

	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	var obj UE
	ue = &obj
	json.Unmarshal(bytes, ue)

	ue.PowerON()

	return
}

func (ue *UE) PowerON() {
	ue.dbgLevel = 0

	ue.state5GMM = state5GMMDeregistared
	ue.Recv.state = rcvdNull

	ue.wa.forceRINMR = true
}

func (ue *UE) Receive(pdu *[]byte) {
	ue.Decode(pdu)
	return
}

func (ue *UE) MakeNasPdu() (pdu []byte) {

	ue.dprint("MakeNasPdu: called in %s", rcvdStateStr[ue.Recv.state])

	switch ue.Recv.state {
	case rcvdNull:
	case rcvdAuthenticationRequest:
		pdu = ue.MakeAuthenticationResponse()
	case rcvdSecurityModeCommand:
		pdu = ue.MakeSecurityModeComplete()
	case rcvdRegistrationAccept:
		pdu = ue.MakeRegistrationComplete()
		ue.dprint("GNBSIM: [REGISTERED]")
	}
	return
}

func (ue *UE) Decode(pdu *[]byte) (msgType int) {

	ue.DecodeError = nil

	epd := readPduByte(pdu)
	ue.dprint("EPD: %s (0x%x)", epdStr[epd], epd)

	if epd == EPD5GSMobilityManagement {
		msgType = ue.Decode5GMM(pdu)
		return
	}
	msgType = ue.Decode5GSM(pdu)
	return
}

// 8.2 5GS mobility management messages
func (ue *UE) Decode5GMM(pdu *[]byte) (msgType int) {

	secHeader := readPduByte(pdu)
	ue.dprint("Security Header: 0x%x", secHeader)

	if secHeader != 0x00 && ue.wa.securityHeaderParsed == false {
		mac := readPduByteSlice(pdu, 4)
		ue.dprinti("mac: %x", mac)

		seq := uint8((*pdu)[0])
		ue.dprinti("seq: %d", seq)

		macCalc := ue.ComputeMAC(1, pdu)
		if reflect.DeepEqual(mac, macCalc) == false {
			ue.DecodeError = fmt.Errorf("nas: integrity checking failed")
			ue.dprint("***** Integrity check failed...")
			ue.dprint("Received  : %x", mac)
			ue.dprint("Calculated: %x", macCalc)
			*pdu = []byte{}
			return
		}
		ue.dprint("***** Integrity check passed")

		readPduByte(pdu)

		ue.wa.securityHeaderParsed = true
		msgType = ue.Decode(pdu)
		return
	}

	if secHeader != 0x00 {
		/*
		 * free5gc seems to set the security header != 0 for the plain NAS
		 * message. My workaround is invoked.
		 */
		ue.dprinti("### workaround: SecurityHeaderParsed.")
	}

	msgType = ue.decMessageType(pdu)

	ue.indent++
	switch msgType {
	case MessageTypeRegistrationAccept:
		ue.decRegistrationAccept(pdu)
		break
	case MessageTypeAuthenticationRequest:
		ue.decAuthenticationRequest(pdu)
		break
	case MessageTypeSecurityModeCommand:
		ue.decSecurityModeCommand(pdu)
		break
	case MessageTypeDLNasTransport:
		ue.decDLNasTransport(pdu)
		break
	default:
		break
	}
	ue.indent--
	ue.wa.securityHeaderParsed = false

	return
}

// 8.3 5GS session management messages
func (ue *UE) Decode5GSM(pdu *[]byte) (msgType int) {

	ue.decPDUSessionIdentity(pdu)
	ue.decProcedureTransactionIdentity(pdu)

	msgType = ue.decMessageType(pdu)

	ue.indent++
	switch msgType {
	case MessageTypePDUSessionEstablishmentAccept:
		ue.decPDUSessionEstablishmentAccept(pdu)
		break
	default:
		break
	}
	ue.indent--

	return
}

func (ue *UE) decInformationElement(pdu *[]byte, ieStrMap map[int]string) {

	for len(*pdu) > 0 {

		iei := int((*pdu)[0])

		// see Annex K.1 Common information elements in TS 24.008.
		type1ie := false
		if iei&0x80 != 0 {
			type1ie = true
			iei >>= 4
		}

		msg := ieStrMap[iei]

		if msg == "" {
			break
		}

		ue.dprint("%s: 0x%x", msg, iei)

		if type1ie {
			(*pdu)[0] &= 0x0f
		} else {
			readPduByte(pdu)
		}

		switch iei {
		case ieiIMEISVRequest:
			ue.decIMEISVRequest(pdu)
		case ieiPDUSessionID2:
			ue.decPDUSessionID2(pdu)
		case ieiNSSAI:
			ue.decNSSAI(pdu)
		case ieiGPRSTimer2:
			ue.decGPRSTimer2(pdu)
		case ieiAuthParamAUTN:
			ue.decAuthParamAUTN(pdu)
		case ieiAuthParamRAND:
			ue.decAuthParamRAND(pdu)
		case ieiPDUAddress:
			ue.decPDUAddress(pdu)
		case ieiAdditional5GSecInfo:
			ue.decAdditional5GSecInfo(pdu)
		case ieiTAIList:
			ue.decTAIList(pdu)
		case iei5GSMCause:
			ue.dec5GSMCause(pdu)
		case ieiGPRSTimer3:
			ue.decGPRSTimer3(pdu)
		case iei5GSMobileIdentity:
			ue.dec5GSMobileID(pdu)
		default:
			ue.dprint("info: This IE(0x%x) has not been supported yet.", iei)
			*pdu = []byte{}
		}
	}
}

// 8.2.1 Authentication request
var ieStrAuthReq = map[int]string{
	ieiAuthParamAUTN: "Authentication Parameter AUTN IE",
	ieiAuthParamRAND: "Authentication Parameter RAND IE",
}

func (ue *UE) decAuthenticationRequest(pdu *[]byte) {
	ue.dprint("Authentication Request")

	orig := ue.indent
	ue.indent++
	ue.dprint("ngKSI IE")
	ue.decNASKeySetIdentifier(pdu)

	ue.dprint("ABBA IE")
	ue.decABBA(pdu)

	ue.decInformationElement(pdu, ieStrAuthReq)
	ue.indent--

	k, _ := hex.DecodeString(ue.AuthParam.K)
	opc, _ := hex.DecodeString(ue.AuthParam.OPc)
	amf := binary.BigEndian.Uint16(ue.AuthParam.amf)

	m := milenage.NewWithOPc(k, opc, ue.AuthParam.rand, 0, amf)
	m.F2345()
	for n, v := range ue.AuthParam.seqxorak {
		m.SQN[n] = v ^ m.AK[n]
	}
	m.F1()

	ue.indent++
	/*
		ue.dprint("K   : %x", m.K)
		ue.dprint("OP  : %x", m.OP)
		ue.dprint("OPc : %x", m.OPc)
		ue.dprint("AMF : %x", m.AMF)
		ue.dprint("SQN : %x", m.SQN)
		ue.dprint("CK  : %x", m.CK)
		ue.dprint("IK  : %x", m.IK)
		ue.dprint("AK  : %x", m.AK)
		ue.dprint("MACA: %x", m.MACA)
		ue.dprint("MACS: %x", m.MACS)
		ue.dprint("RAND: %x", m.RAND)
		ue.dprint("RES : %x", m.RES)
	*/

	if reflect.DeepEqual(ue.AuthParam.mac, m.MACA) == false {
		ue.dprinti("received and calculated MAC values do not match.\n")
		ue.indent = orig
		// need response for error.
		return
	}

	ue.ComputeKausf(m.CK, m.IK)
	ue.ComputeKseaf()
	ue.ComputeKamf()
	ue.ComputeAlgKey()

	ue.ComputeRESstar(m.RAND, m.RES, m.CK, m.IK)

	/*
		ue.dprint("Kausf: %x", ue.AuthParam.Kausf)
		ue.dprint("Kseaf: %x", ue.AuthParam.Kseaf)
		ue.dprint("Kamf : %x", ue.AuthParam.Kamf)
		ue.dprint("Kenc : %x", ue.AuthParam.Kenc)
		ue.dprint("Kint : %x", ue.AuthParam.Kint)
		ue.dprint("RES* : %x", ue.AuthParam.RESstar)
	*/
	ue.dprint("received and calculated MAC values match.")
	ue.indent = orig

	ue.Recv.state = rcvdAuthenticationRequest

	return
}

// 8.2.2 Authentication response
func (ue *UE) MakeAuthenticationResponse() (pdu []byte) {

	pdu = ue.enc5GSMMMessageHeader(SecurityHeaderTypePlain,
		MessageTypeAuthenticationResponse)

	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, ue.encAuthParamRes())
	pdu = append(pdu, data.Bytes()...)

	return
}

// 8.2.6 Registration request
// 5.5.1.2 Registration procedure for initial registration
func (ue *UE) MakeRegistrationRequest() (pdu []byte) {

	pdu = ue.enc5GSMMMessageHeader(SecurityHeaderTypePlain,
		MessageTypeRegistrationRequest)

	tmp := ue.encRegistrationType()
	pdu = append(pdu, ue.encNASKeySetIdentifier(&tmp)...)
	pdu = append(pdu, ue.enc5GSMobileID(false, TypeIDSUCI)...)

	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, enc5GMMCapability())
	binary.Write(data, binary.BigEndian, encUESecurityCapability())
	pdu = append(pdu, data.Bytes()...)

	ue.state5GMM = state5GMMRegisteredInitiated

	// start T3510 timer. see 5.5.1.2.2 Initial registration initiation

	return
}

// 8.2.7 Registration accept
var ieStrRegAcc = map[int]string{
	ieiNSSAI:             "Allowed NSSAI",
	ieiGPRSTimer2:        "T3502 value",
	ieiTAIList:           "TAI list",
	ieiGPRSTimer3:        "T3512 value",
	iei5GSMobileIdentity: "5G-GUTI",
}

func (ue *UE) decRegistrationAccept(pdu *[]byte) {

	ue.dprint("Registration Accept")

	ue.indent++
	ue.dprint("5GS registration result IE")
	ue.dec5GSRegistrationResult(pdu)
	ue.decInformationElement(pdu, ieStrRegAcc)
	ue.indent--

	ue.Recv.state = rcvdRegistrationAccept

	return
}

// 8.2.8 Registration complete
func (ue *UE) MakeRegistrationComplete() (pdu []byte) {

	pdu = ue.enc5GSMMMessageHeader(
		SecurityHeaderTypePlain,
		MessageTypeRegistrationComplete)

	head := ue.enc5GSecurityProtectedMessageHeader(
		SecurityHeaderTypeIntegrityProtectedAndCipheredWithNewContext, &pdu)

	pdu = append(head, pdu...)

	return
}

// 8.2.10 UL NAS transport
func (ue *UE) MakeULNasTransport(
	payloadType uint8, msgType uint8, payload *[]byte) (pdu []byte) {

	pdu = ue.enc5GSMMMessageHeader(
		SecurityHeaderTypePlain,
		MessageTypeULNasTransport)

	pdu = append(pdu, byte(payloadType))

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(*payload)))
	pdu = append(pdu, length...)
	pdu = append(pdu, *payload...)

	if payloadType == PayloadContainerN1SMInformation {
		pdu = append(pdu, ue.encPDUSessionID2(ue.sm.pduSessionId)...)
	}

	switch msgType {
	case MessageTypePDUSessionEstablishmentRequest:
		pdu = append(pdu, ue.encRequestType(RequestTypeInitialRequest)...)
	}

	if payloadType == PayloadContainerN1SMInformation &&
		msgType == MessageTypePDUSessionEstablishmentRequest {
		pdu = append(pdu, ue.encSNSSAI()...)
		pdu = append(pdu, ue.encDNN()...)
	}

	return
}

// 8.2.11 DL NAS transport
var ieStrDLNasTransport = map[int]string{
	ieiPDUSessionID2: "PDU session ID",
	//	ieiAdditionalInformation: ieStr[ieiAdditionalInformation],
	//	iei5GMMCause:             ieStr[iei5GMMCause],
	//	ieiBackoffTimerValue:     ieStr[ieiBackoffTimerValue],
}

func (ue *UE) decDLNasTransport(pdu *[]byte) {

	ue.dprint("DL NAS Transport")

	ue.indent++
	ue.dprint("Payload container type")
	ue.decPayloadContainerType(pdu)

	ue.dprint("Payload container")
	ue.decPayloadContainer(pdu)

	ue.decInformationElement(pdu, ieStrDLNasTransport)
	ue.indent--

	return
}

// 8.2.12 De-registration request (UE originating de-registration)
func (ue *UE) MakeDeregistrationRequest() (pdu []byte) {

	pdu = ue.enc5GSMMMessageHeader(SecurityHeaderTypePlain,
		MessageTypeDeregistrationRequest)
	tmp := ue.encDeregistrationType()
	pdu = append(pdu, ue.encNASKeySetIdentifier(&tmp)...)

	// see detail is shown in 5.5.2.2 UE-initiated de-registration procedure
	pdu = append(pdu, ue.enc5GSMobileID(false, TypeID5GGUTI)...)
	head := ue.enc5GSecurityProtectedMessageHeader(
		SecurityHeaderTypeIntegrityProtectedAndCipheredWithNewContext,
		&pdu)

	pdu = append(head, pdu...)
	return
}

// 8.2.25 Security mode command
var ieStrSecModeCmd = map[int]string{
	ieiIMEISVRequest:       ieStr[ieiIMEISVRequest],
	ieiAdditional5GSecInfo: ieStr[ieiAdditional5GSecInfo],
}

func (ue *UE) decSecurityModeCommand(pdu *[]byte) {

	ue.dprint("Security Mode Command")

	ue.indent++
	ue.dprint("Selected NAS security algorithms IE")
	ue.decNASSecurityAlgorithms(pdu)

	ue.dprint("ngKSI IE")
	ue.decNASKeySetIdentifier(pdu)

	ue.dprint("Replayed UE security capabilities IE")
	ue.decUESecurityCapability(pdu)

	ue.decInformationElement(pdu, ieStrSecModeCmd)
	ue.indent--

	ue.Recv.state = rcvdSecurityModeCommand

	return
}

// 8.2.26 Security mode complete
func (ue *UE) MakeSecurityModeComplete() (pdu []byte) {

	pdu = ue.enc5GSMMMessageHeader(
		SecurityHeaderTypePlain,
		MessageTypeSecurityModeComplete)

	if ue.Recv.flag.imeisv {
		pdu = append(pdu, ue.enc5GSMobileID(true, TypeIDIMEISV)...)
		ue.Recv.flag.imeisv = false
	}

	if ue.Recv.flag.rinmr || ue.wa.forceRINMR {
		pdu = append(pdu,
			ue.encNASMessageContainer(true, MessageTypeRegistrationRequest)...)
		ue.Recv.flag.rinmr = false
	}

	head := ue.enc5GSecurityProtectedMessageHeader(
		SecurityHeaderTypeIntegrityProtectedAndCipheredWithNewContext, &pdu)

	pdu = append(head, pdu...)

	return
}

// 8.3.1 PDU session establishment request
func (ue *UE) MakePDUSessionEstablishmentRequest() (pdu []byte) {

	ue.sm.pduSessionId = 0x01
	ue.sm.procedureTransactionId = 0x01

	pdu = ue.enc5GSSMMessageHeader(
		ue.sm.pduSessionId,           // 9.4 PDU Session ID
		ue.sm.procedureTransactionId, // 9.6 Procedure Transaction ID
		MessageTypePDUSessionEstablishmentRequest)

	pdu = append(pdu, ue.encIntegrityProtectionMaximuDataRate()...)
	pdu = append(pdu, ue.encPDUSessionType()...)

	pdu = ue.MakeULNasTransport(
		PayloadContainerN1SMInformation,
		MessageTypePDUSessionEstablishmentRequest, &pdu)

	head := ue.enc5GSecurityProtectedMessageHeader(
		SecurityHeaderTypeIntegrityProtectedAndCiphered, &pdu)

	pdu = append(head, pdu...)

	return
}

// 8.3.2 PDU session establishment accept
var ieStrPSEAccept = map[int]string{
	ieiPDUAddress: ieStr[ieiPDUAddress],
	iei5GSMCause:  ieStr[iei5GSMCause],
}

func (ue *UE) decPDUSessionEstablishmentAccept(pdu *[]byte) {

	ue.dprint("PDU Session Establishment Accept")

	ue.indent++
	ue.dprint("Selected PDU session type")
	ue.decPDUSessionType(false, pdu)

	ue.dprint("Selected SSC mode")
	ue.decSSCMode(false, pdu)
	*pdu = (*pdu)[1:]

	ue.dprint("Authorized QoS rules")
	ue.decQoSRules(pdu)

	ue.dprint("Session AMBR")
	ue.decSessionAMBR(pdu)

	ue.decInformationElement(pdu, ieStrPSEAccept)

	ue.indent--

	return
}

// 9.1.1 NAS message format
func (ue *UE) enc5GSMMMessageHeader(
	headType uint8, msgType uint8) (head []byte) {

	head = append(head, EPD5GSMobilityManagement)
	head = append(head, headType)
	head = append(head, msgType)

	return
}

func (ue *UE) enc5GSSMMessageHeader(
	psi uint8, pti uint8, msgType uint8) (head []byte) {

	head = append(head, EPD5GSSessionManagement)
	head = append(head, psi)
	head = append(head, pti)
	head = append(head, msgType)

	return
}

func (ue *UE) enc5GSecurityProtectedMessageHeader(
	headType uint8, pdu *[]byte) (head []byte) {

	head = append(head, []byte{EPD5GSMobilityManagement}...)
	head = append(head, []byte{headType}...)

	seq := []byte{uint8(ue.NasCount)}
	*pdu = append(seq, *pdu...)

	mac := ue.ComputeMAC(0, pdu)
	head = append(head, mac...)

	ue.NasCount++

	return
}

// 9.4 PDU session identity
func (ue *UE) decPDUSessionIdentity(pdu *[]byte) {

	id := int((*pdu)[0])
	*pdu = (*pdu)[1:]
	ue.dprint("PDU Session Identity: 0x%x", id)
	return
}

// 9.6 Procedure transaction identity
func (ue *UE) decProcedureTransactionIdentity(pdu *[]byte) {
	id := int((*pdu)[0])
	*pdu = (*pdu)[1:]
	ue.dprint("Procedure Transaction Identity: 0x%x", id)
	return
}

// 9.7 Message type
func (ue *UE) decMessageType(pdu *[]byte) (msgType int) {
	msgType = int((*pdu)[0])
	ue.dprint("Message Type: %s (0x%x)", msgTypeStr[msgType], msgType)
	*pdu = (*pdu)[1:]
	return
}

// 9.11.2.1B DNN
func (ue *UE) encDNN() (pdu []byte) {

	pdu = append(pdu, byte(ieiDNN))

	dnn := []byte{}
	for _, str := range strings.Split(ue.DNN, ".") {
		dnn = append(dnn, byte(len(str)))
		dnn = append(dnn, []byte(str)...)
	}

	pdu = append(pdu, byte(len(dnn)))
	pdu = append(pdu, dnn...)

	return
}

// 9.11.2.4 GPRS timer 2
// See subclause 10.5.7.4 in 3GPP TS 24.008.
func (ue *UE) decGPRSTimer2(pdu *[]byte) {

	tmp := int((*pdu)[1])

	multiple := 2 // 2 seconds
	switch tmp >> 5 {
	case 0x1:
		multiple = 60 // 1 minute
	case 0x2:
		multiple = 60 * 60 / 10 // 1 decihours
	case 0x7:
		multiple = 0 // deactivated
	}

	ue.Recv.t3502 = (tmp & 0x1f) * multiple
	*pdu = (*pdu)[2:]
	ue.dprinti("GPRS timer 2: %d sec", ue.Recv.t3502)

	return
}

// 9.11.2.5 GPRS timer 3
// See subclause 10.5.7.4a in 3GPP TS 24.008.
func (ue *UE) decGPRSTimer3(pdu *[]byte) {

	tmp := int((*pdu)[1])

	multiple := 60 * 10 // 60 minutes
	switch tmp >> 5 {
	case 0x1:
		multiple = 60 * 60 // 1 hour
	case 0x2:
		multiple = 60 * 60 * 10 // 10 hours
	case 0x3:
		multiple = 2 // 2 seconds
	case 0x4:
		multiple = 30 // 30 seconds
	case 0x5:
		multiple = 60 // 1 minute
	case 0x6:
		multiple = 230 * 60 * 60 // 320 hours
	case 0x7:
		multiple = 0 // deactivated
	}

	ue.Recv.t3512 = (tmp & 0x1f) * multiple
	*pdu = (*pdu)[2:]
	ue.dprinti("GPRS timer 3: %d sec", ue.Recv.t3512)
	return
}

// 9.11.2.8 S-NSSAI
type SNSSAI struct {
	SST       int
	SD        string
	mappedsst int
	mappedsd  string
}

func (ue *UE) decSNSSAI(iei bool, pdu *[]byte) (snssai SNSSAI) {

	if iei == true {
		ue.dprint("error: decSNSSAI with iei not supported yet.")
		return
	}

	ue.dprinti("S-NSSAI")

	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	ue.indent++
	snssai.SST = int((*pdu)[0])
	*pdu = (*pdu)[1:]
	ue.dprinti("SST: %d", snssai.SST)

	switch length {
	case 4, 5, 8:
		snssai.SD = hex.EncodeToString((*pdu)[:3])
		*pdu = (*pdu)[3:]
		ue.dprinti("SD: 0x%s", snssai.SD)
	}

	switch length {
	case 2, 5, 8:
		snssai.mappedsst = int((*pdu)[0])
		*pdu = (*pdu)[1:]
		ue.dprinti("Mapped HPLMN SST: %d", snssai.mappedsst)
	}

	if length == 8 {
		snssai.mappedsd = hex.EncodeToString((*pdu)[:3])
		*pdu = (*pdu)[3:]
		ue.dprinti("Mapped HPLMN SD: 0x%s", snssai.mappedsd)
	}
	ue.indent--

	return
}

func (ue *UE) encSNSSAI() (pdu []byte) {

	pdu = append(pdu, byte(ieiSNSSAI))
	pdu = append(pdu, byte(4)) // length: sst = 1, ssd = 3
	pdu = append(pdu, byte(ue.SNSSAI.SST))

	tmp, _ := hex.DecodeString(ue.SNSSAI.SD)
	pdu = append(pdu, tmp...)

	return
}

// 9.11.3.1 5GMM capability
type FiveGMMCapability struct {
	iei         uint8
	length      uint8
	capability1 uint8
}

const (
	FiveGMMCapN3data = 0x20
)

func enc5GMMCapability() (pdu []byte) {

	var f FiveGMMCapability

	f.iei = 0x10
	f.length = 1
	f.capability1 = FiveGMMCapN3data

	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, f)
	pdu = data.Bytes()

	return
}

// 9.11.3.4 5GS mobile identity
// I need C 'union' for golang...
const (
	TypeIDNoIdentity = iota
	TypeIDSUCI
	TypeID5GGUTI
	TypeIDIMEI
	TypeID5GSTMSI
	TypeIDIMEISV
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

func (ue *UE) enc5GSMobileID(iei bool, typeID int) (pdu []byte) {

	if iei == true {
		pdu = append(pdu, []byte{iei5GSMobileIdentity}...)
	}

	switch typeID {
	//case TypeIDNoIdentity:
	case TypeIDSUCI:
		pdu = append(pdu, ue.enc5GSMobileIDTypeSUCI()...)
	case TypeID5GGUTI:
		pdu = append(pdu, ue.enc5GSMobileIDType5GGUTI()...)
	//case TypeIDIMEI:
	//case TypeID5GSTMSI:
	case TypeIDIMEISV:
		pdu = append(pdu, ue.enc5GSMobileIDTypeIMEISV()...)
	}
	return
}

type FiveGSMobileIDSUCI struct {
	length                 uint16
	supiFormatAndTypeID    uint8
	plmn                   [3]uint8
	routingIndicator       [2]uint8
	protectionScheme       uint8
	homeNetworkPublicKeyID uint8
	schemeOutput           [5]uint8
}

func (ue *UE) enc5GSMobileIDTypeSUCI() (pdu []byte) {

	var f FiveGSMobileIDSUCI
	var typeID uint8 = TypeIDSUCI
	var supiFormat uint8 = SUPIFormatIMSI

	/*
	 * it doesn't work with "f.length = uint16(unsafe.Sizeof(*f) - 2)"
	 * because of the octet alignment.
	 */
	f.length = 13
	f.supiFormatAndTypeID = typeID | (supiFormat << 4)
	f.plmn = encPLMN(ue.MCC, ue.MNC)
	f.routingIndicator = encRoutingIndicator(ue.RoutingIndicator)
	f.protectionScheme = encProtectionScheme(ue.ProtectionScheme)
	f.homeNetworkPublicKeyID = 0
	f.schemeOutput = encSchemeOutput(ue.MSIN)

	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, f)
	pdu = data.Bytes()

	return
}

func (ue *UE) enc5GSMobileIDType5GGUTI() (pdu []byte) {

	id := byte(TypeID5GGUTI)
	id |= 0xf0
	pdu = append(pdu, id)
	pdu = append(pdu, ue.Recv.fiveGGUTI...)

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(pdu)))
	pdu = append(length, pdu...)
	return
}

type FiveGSMobileIDIMEISV struct {
	length uint16
	imeisv [9]byte
}

func (ue *UE) enc5GSMobileIDTypeIMEISV() (pdu []byte) {

	var f FiveGSMobileIDIMEISV
	var typeID uint8 = TypeIDIMEISV

	f.length = 9

	if len(ue.IMEISV)/2 == 1 {
		typeID |= 0x08 // odd even bit
	}

	imeisv := fmt.Sprintf("%x%sf", typeID, ue.IMEISV)
	for i, v := range Str2BCD(imeisv) {
		f.imeisv[i] = v
	}
	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, f)
	pdu = data.Bytes()

	return
}

func encPLMN(mcc, mnc int) (plmn [3]byte) {
	format := "%d%d"
	if mnc < 100 {
		format = "%df%02d"
	}

	str := fmt.Sprintf(format, mcc, mnc)
	for i, v := range Str2BCD(str) {
		plmn[i] = v
	}
	return
}

func (ue *UE) decPLMN(pdu *[]byte) (mcc, mnc int) {

	oct1 := int((*pdu)[0])
	oct2 := int((*pdu)[1])
	oct3 := int((*pdu)[2])
	*pdu = (*pdu)[3:]

	mcc = (oct1 & 0xf) * 100
	mcc = mcc + 10*(oct1>>4)
	mcc = mcc + (oct2 & 0xf)

	mnc = 0
	if (oct2 & 0xf0) != 0xf0 {
		mnc = 100 * (oct2 >> 4)
	}
	mnc = mnc + 10*(oct3&0xf)
	mnc = mnc + (oct3 >> 4)

	ue.dprinti("MCC: %d", mcc)
	ue.dprinti("MNC: %d", mnc)

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

func (ue *UE) dec5GSMobileID(pdu *[]byte) {

	ue.dprinti("5GS mobile identity")
	length := readPduUint16(pdu)
	tmp := readPduByte(pdu)
	id := int(tmp & 0x7)
	length--

	ue.indent++
	switch id {
	case TypeID5GGUTI:
		ue.dec5GSMobileIDType5GGUTI((*pdu)[:length])
	}
	ue.indent--
	*pdu = (*pdu)[length:]

	return
}

func (ue *UE) dec5GSMobileIDType5GGUTI(pdu []byte) {
	ue.Recv.fiveGGUTI = pdu
	ue.dprinti("5G-GUTI: %x", ue.Recv.fiveGGUTI)
	return
}

// 9.11.3.6 5GS registration result
const (
	regResultNull = iota
	regResult3GPP
	regResultNon3GPP
	regResult3GPPandNon3GPP
)

var regResultStr = map[uint8]string{
	regResult3GPP:           "3GPP access",
	regResultNon3GPP:        "Non-3GPP access",
	regResult3GPPandNon3GPP: "3GPP access and non-3GPP access",
}

func (ue *UE) dec5GSRegistrationResult(pdu *[]byte) {

	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]
	val := (*pdu)[:length]
	*pdu = (*pdu)[length:]

	ue.indent++
	ue.dprint("5G Registration Result: %x", val)
	result := uint8(val[0])

	not := "R"
	if result&0x20 == 0 {
		not = "Not r"
	}
	ue.dprinti("%segistered for emergency services", not)

	not = ""
	if result&0x10 == 0 {
		not = "not "
	}
	ue.dprinti("Network slice-specific authentication and authorization is %sto be performed", not)

	not = ""
	if result&0x8 == 0 {
		not = "not "
	}
	ue.dprinti("SMS over NAS %sallowed", not)

	ind := result & 0x7
	ue.dprinti(regResultStr[ind])
	ue.indent--

	return
}

// 9.11.3.7 5GS registration type
const (
	RegistrationTypeInitialRegistration        = 0x01
	RegistrationTypeFlagFollowOnRequestPending = 0x08
)

func (ue *UE) encRegistrationType() (pdu []byte) {

	pdu = []byte{RegistrationTypeInitialRegistration |
		RegistrationTypeFlagFollowOnRequestPending}
	return
}

// 9.11.3.9 5GS tracking area identity list
func (ue *UE) decTAIList(pdu *[]byte) {
	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	tmp := (*pdu)[0]
	elementNum := int(tmp&0x1f) + 1
	typeOfList := tmp >> 5
	*pdu = (*pdu)[1:]

	ue.indent++
	ue.dprint("5GS tracking area identity list")
	ue.dprinti("number of element: %d", elementNum)
	ue.dprinti("type of list: 0x%x", typeOfList)

	switch typeOfList {
	case 0x00:
		ue.decTAIListType00(pdu, elementNum)
		/*
			case 0x01:
				break
			case 0x10:
				break
		*/
	default:
		ue.dprinti("unknown list type: 0x%x", typeOfList)
		*pdu = (*pdu)[length:]
	}
	ue.indent--
	return
}

type TAI struct {
	mcc int
	mnc int
	tac []byte
}

func (ue *UE) decTAIListType00(pdu *[]byte, num int) {

	mcc, mnc := ue.decPLMN(pdu)

	const tacSize = 3
	for num > 0 {
		tac := (*pdu)[:tacSize]
		*pdu = (*pdu)[tacSize:]
		ue.Recv.tai = append(ue.Recv.tai, TAI{mcc, mnc, tac})
		ue.dprinti("tac: 0x%x", tac)
		num--
	}
	return
}

// 9.11.3.10 ABBA
func (ue *UE) decABBA(pdu *[]byte) {

	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]
	ue.AuthParam.abba = (*pdu)[:length]
	*pdu = (*pdu)[length:]

	ue.indent++
	ue.dprint("ABBA")
	ue.dprinti("Length: %d", length)
	ue.dprinti("Value: 0x%02x", ue.AuthParam.abba)
	ue.indent--

	return
}

// 9.11.3.12 Additional 5G security information
func (ue *UE) decAdditional5GSecInfo(pdu *[]byte) {

	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	if length != 1 {
		ue.dprinti("unexpected length: %d", length)
		*pdu = (*pdu)[length:]
		return
	}

	ue.indent++
	val := int((*pdu)[0])
	ue.dprint("value: 0x%x", val)

	not := ""
	if val&0x01 == 0x00 {
		not = "not "
	}
	ue.dprinti("KAMF derivation is %srequired", not)

	ue.Recv.flag.rinmr = true
	not = ""
	if val&0x02 == 0x00 {
		not = "not "
		ue.Recv.flag.rinmr = false
	}
	ue.dprinti("Retransmission of the initial NAS message %srequested", not)

	ue.indent--
	*pdu = (*pdu)[length:]
	return
}

// 9.11.3.15 Authentication parameter AUTN
// TS 24.008 10.5.3.1.1 Authentication Parameter AUTN (UMTS and EPS authentication challenge)
type AuthParam struct {
	K        string
	OPc      string
	rand     []byte
	autn     []byte
	seqxorak []byte
	amf      []byte
	mac      []byte
	abba     []byte
	RESstar  []byte
	Kausf    []byte
	Kseaf    []byte
	Kamf     []byte
	Kenc     []byte
	Kint     []byte
}

func (ue *UE) decAuthParamAUTN(pdu *[]byte) {

	autnlen := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	ue.AuthParam.autn = (*pdu)[:autnlen]
	*pdu = (*pdu)[autnlen:]
	ue.dprinti("AUTN: %02x", ue.AuthParam.autn)
	ue.AuthParam.seqxorak = ue.AuthParam.autn[:6]
	ue.AuthParam.amf = ue.AuthParam.autn[6:8]
	ue.AuthParam.mac = ue.AuthParam.autn[8:16]
	ue.dprinti("SEQ xor AK: %02x", ue.AuthParam.seqxorak)
	ue.dprinti("AMF       : %02x", ue.AuthParam.amf)
	ue.dprinti("MAC       : %02x", ue.AuthParam.mac)

	return
}

// 9.11.3.16 Authentication parameter RAND
// TS 24.008 10.5.3.1 Authentication parameter RAND
func (ue *UE) decAuthParamRAND(pdu *[]byte) {

	const randlen = 16
	ue.AuthParam.rand = (*pdu)[:randlen]
	*pdu = (*pdu)[randlen:]
	ue.dprinti("RAND: 0x%02x", ue.AuthParam.rand)
	return
}

// 9.11.3.17 Authentication response parameter
// TS 24.301 9.9.3.4 Authentication response parameter
type AuthParamRes struct {
	iei     uint8
	length  uint8
	resstar [16]byte
}

func (ue *UE) encAuthParamRes() (res AuthParamRes) {
	res.iei = ieiAuthParamRES
	for i, v := range ue.AuthParam.RESstar {
		res.resstar[i] = v
	}
	res.length = uint8(len(res.resstar))

	//	data := new(bytes.Buffer)
	//	binary.Write(data, binary.BigEndian, ue.encAuthParamRes())
	//	pdu = append(pdu, data.Bytes()...)

	return
}

// 9.11.3.20 De-registration type
const (
	accessTypeNull = iota
	accessType3GPP
	accessTypeNon3GPP
	accessType3GPPandNon3GPP
)

func (ue *UE) encDeregistrationType() (pdu []byte) {

	pdu = []byte{0}
	switchOff := false
	if switchOff {
		pdu[0] |= (1 << 3)
	}
	pdu[0] |= accessType3GPP
	return
}

// 9.11.3.28 IMEISV request
// TS 24.008 9.11.3.28 IMEISV request
func (ue *UE) decIMEISVRequest(pdu *[]byte) {

	val := int((*pdu)[0])
	ue.dprinti("value: 0x%x", val)
	if val&0x01 != 0 {
		ue.Recv.flag.imeisv = true
	}
	*pdu = (*pdu)[1:]
	return
}

// 9.11.3.32 NAS key set identifier
const (
	KeySetIdentityNoKeyIsAvailable          = 0x07
	KeySetIdentityFlagMappedSecurityContext = 0x08
)

func (ue *UE) decNASKeySetIdentifier(pdu *[]byte) {

	ksi := int((*pdu)[0])
	ue.dprinti("NAS key set identifier: 0x%x", ksi)
	*pdu = (*pdu)[1:]

	return
}

func (ue *UE) encNASKeySetIdentifier(type1ie *[]byte) (pdu []byte) {

	if type1ie == nil {
		pdu = []byte{KeySetIdentityNoKeyIsAvailable}
		return
	}
	pdu = []byte{(*type1ie)[0] | KeySetIdentityNoKeyIsAvailable<<4}
	return
}

// 9.11.3.33 NAS message container
func (ue *UE) encNASMessageContainer(iei bool, msgType int) (pdu []byte) {

	if iei == true {
		pdu = append(pdu, []byte{ieiNASMessageContainer}...)
	}

	tmp := []byte{}
	switch msgType {
	case MessageTypeRegistrationRequest:
		tmp = ue.MakeRegistrationRequest()
	default:
	}

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(tmp)))

	pdu = append(pdu, length...)
	pdu = append(pdu, tmp...)

	return
}

// 9.11.3.34 NAS security algorithms
func (ue *UE) decNASSecurityAlgorithms(pdu *[]byte) {

	alg := (*pdu)[:1]
	ue.dprinti("NAS Security Algorithms: 0x%02x", alg)
	*pdu = (*pdu)[1:]

	return
}

// 9.11.3.37 NSSAI
func (ue *UE) decNSSAI(pdu *[]byte) {

	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	for length > 0 {
		lenBefore := len(*pdu)
		snssai := ue.decSNSSAI(false, pdu)
		ue.Recv.allowedNSSAI = append(ue.Recv.allowedNSSAI, snssai)

		lenAfter := len(*pdu)
		length -= lenBefore - lenAfter
	}

	return
}

// 9.11.3.39 Payload container
func (ue *UE) decPayloadContainer(pdu *[]byte) {

	ue.indent++
	length := int(binary.BigEndian.Uint16(*pdu))
	*pdu = (*pdu)[2:]
	ue.dprint("Length: %d", length)
	payload := readPduByteSlice(pdu, length)
	ue.Decode(&payload)
	ue.indent--

	return
}

// 9.11.3.40 Payload container type
const (
	PayloadContainerN1SMInformation = 0x1
)

var payloadContainerStr = map[int]string{
	PayloadContainerN1SMInformation: "N1 SM Information",
}

func (ue *UE) decPayloadContainerType(pdu *[]byte) {

	ctype := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	ue.dprinti("Type: %s(0x%x)",
		payloadContainerStr[ctype], ctype)

	return
}

// 9.11.3.41 PDU session identity 2
func (ue *UE) decPDUSessionID2(pdu *[]byte) {
	sid := readPduByte(pdu)
	ue.dprinti("PDU session identity 2 value: %d", sid)
	return
}

func (ue *UE) encPDUSessionID2(id uint8) (pdu []byte) {

	pdu = append(pdu, byte(ieiPDUSessionID2))
	pdu = append(pdu, byte(id))

	return
}

// 9.11.3.47 Request type
const (
	RequestTypeInitialRequest = 0x01
)

func (ue *UE) encRequestType(val uint8) (pdu []byte) {
	pdu = []byte{byte((ieiRequestType << 4) | val)}
	return
}

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

func encUESecurityCapability() (sc UESecurityCapability) {
	sc.iei = ieiUESecurityCapability
	sc.length = 4

	// use null encryption at this moment.
	sc.ea = EA0
	sc.ia = IA0 | IA2

	return
}

func (ue *UE) decUESecurityCapability(pdu *[]byte) {

	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	cap := (*pdu)[:length]
	ue.dprinti("Capability: 0x%02x", cap)
	*pdu = (*pdu)[length:]

	return
}

// 9.11.4.2 5GSM cause
const (
	smCausePDUSessionTypeIPv4OnlyeAllowed = 0x32
)

var smCauseStr = map[byte]string{
	smCausePDUSessionTypeIPv4OnlyeAllowed: "PDU session type IPv4 only allowed",
}

func (ue *UE) dec5GSMCause(pdu *[]byte) {

	cause := readPduByte(pdu)
	ue.dprinti("cause: %s(%d)", smCauseStr[cause], cause)

	return
}

// 9.11.4.7 Integrity protection maximum data rate
func (ue *UE) encIntegrityProtectionMaximuDataRate() (pdu []byte) {

	uplink := 0xff
	downlink := 0xff

	pdu = append(pdu, byte(uplink))
	pdu = append(pdu, byte(downlink))
	return
}

// 9.11.4.10 PDU address
func (ue *UE) decPDUAddress(pdu *[]byte) {

	length := readPduByte(pdu)
	ue.dprinti("Length: %d", length)

	pduSessionType := readPduByte(pdu) & 0x7
	ue.dprinti("PDU session type: %s(%d)",
		pduSessionTypeStr[pduSessionType], pduSessionType)

	switch pduSessionType {
	case PDUSessionIPv4:
		ue.Recv.PDUAddress = readPduByteSlice(pdu, net.IPv4len)
		ue.dprinti("PDU address information: %v", ue.Recv.PDUAddress)
	default:
		ue.dprinti("unsupported PDU session type: %d", pduSessionType)
	}

	return
}

// 9.11.4.11 PDU session type
const (
	PDUSessionIPv4   = 0x01
	PDUSessionIPv6   = 0x02
	PDUSessionIPv4v6 = 0x03
)

var pduSessionTypeStr = map[byte]string{
	PDUSessionIPv4:   "IPv4",
	PDUSessionIPv6:   "IPv6",
	PDUSessionIPv4v6: "IPv4v6",
}

func (ue *UE) encPDUSessionType() (pdu []byte) {
	pdu = []byte{byte((ieiPDUSessionType << 4) | PDUSessionIPv4v6)}
	return
}

func (ue *UE) decPDUSessionType(iei bool, pdu *[]byte) {
	pduSessionType := 0x0f & (*pdu)[0]
	ue.dprinti("PDU Session Type: %s(%d)",
		pduSessionTypeStr[pduSessionType], pduSessionType)
	ShiftType1IE(iei, pdu)
	return
}

// 9.11.4.13 QoS rules
func (ue *UE) decQoSRules(pdu *[]byte) {

	ue.indent++
	ue.dprint("QoS rules")

	length := binary.BigEndian.Uint16(*pdu)
	*pdu = (*pdu)[2:]
	ue.dprinti("Length: %d", length)
	remain := int(length)

	for i := 0; remain > 0; i++ {
		ue.indent++
		ue.dprint("Qos rule %d", i)
		remain -= ue.decQoSRule(pdu)
		ue.indent--
	}
	ue.indent--

	return
}

const (
	ruleOpCodeCreateNewQoSRule = 1
)

var ruleOpCodeStr = map[int]string{
	ruleOpCodeCreateNewQoSRule: "Create new QoS rule",
}

func (ue *UE) decQoSRule(pdu *[]byte) (length int) {

	id := int((*pdu)[0])
	*pdu = (*pdu)[1:]
	ue.dprinti("QoS rule identifier: %d", id)
	length = 1

	ruleLen := binary.BigEndian.Uint16(*pdu)
	*pdu = (*pdu)[2:]
	length += 2
	ue.dprinti("Length: %d", ruleLen)
	length += int(ruleLen)

	tmp := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	ruleOpCode := tmp >> 5
	ue.dprinti("Rule operation code: %s(%d)",
		ruleOpCodeStr[ruleOpCode], ruleOpCode)

	not := "not "
	if (tmp>>4)&0x1 != 0 {
		not = ""
	}
	ue.dprinti("the QoS rule is %sthe default QoS rule", not)

	filterNum := int(tmp & 0xf)
	ue.dprinti("Number of packet filters: %d", filterNum)

	for i := 0; i < filterNum; i++ {
		ue.dprinti("packet filter %d", i)
		ue.indent++
		ue.decPacketFilter(pdu)
		ue.indent--
	}

	precedence := int((*pdu)[0])
	*pdu = (*pdu)[1:]
	ue.dprinti("QoS rule precedence: %d", precedence)

	tmp = int((*pdu)[0])
	*pdu = (*pdu)[1:]

	not = "not "
	if (tmp>>6)&0x1 != 0 {
		not = ""
	}
	ue.dprinti("Segregation: Segregation %srequested", not)
	ue.dprinti("QoS flow identifier: QFI%d", tmp&0x3f)

	return
}

const (
	pktFilterDirDownlinkOnly  = 1
	pktFilterDirUplinkOnly    = 2
	pktFilterDirBidirectional = 3
)

var pktFilterDirStr = map[int]string{
	pktFilterDirBidirectional: "Bidirectional",
}

const (
	pktFilterContentMatchAll = 1
)

var pktFilterContentStr = map[int]string{
	pktFilterContentMatchAll: "Match-all type",
}

func (ue *UE) decPacketFilter(pdu *[]byte) {
	tmp := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	tmp &= 0x3f
	ue.dprinti("Packet filter identifier: %d", tmp&0xf)
	ue.dprinti("Packet filter direction: %s", pktFilterDirStr[tmp>>4])

	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]
	ue.dprinti("Length of packet filter contents: %d", length)

	for i := 0; i < length; i++ {
		content := int((*pdu)[0])
		*pdu = (*pdu)[1:]
		ue.dprinti("Packet filter content %d: %s(%d)",
			i, pktFilterContentStr[content], content)
	}
	return
}

// 9.11.4.14 Session-AMBR
const (
	unitAMBRnotUsed = 0
	unitAMBR1Kbps   = 1
	unitAMBR4Kbps   = 2
)

var unitAMBRStr = map[int]string{
	unitAMBRnotUsed: "not used",
	unitAMBR1Kbps:   "1Kbps",
	unitAMBR4Kbps:   "4Kbps",
}

func (ue *UE) decSessionAMBR(pdu *[]byte) {
	length := readPduByte(pdu)
	ue.dprinti("Length of Session-AMBR contents: %d", length)

	unitDL := int(readPduByte(pdu))
	ue.dprinti("unit for Session-AMBR for downlink: %s(%d)",
		unitAMBRStr[unitDL], unitDL)

	ambrDL := readPduUint16(pdu)
	ue.dprinti("Session-AMBR for downlink: %d", ambrDL)

	unitUL := int(readPduByte(pdu))
	ue.dprinti("unit for Session-AMBR for uplink: %s(%d)",
		unitAMBRStr[unitUL], unitDL)

	ambrUL := readPduUint16(pdu)
	ue.dprinti("Session-AMBR for uplink: %d", ambrUL)
	return
}

// 9.11.4.16 SSC mode
func (ue *UE) decSSCMode(iei bool, pdu *[]byte) {
	ssc := 0x0f & int((*pdu)[0])
	ue.dprinti("SSC Mode: SSC mode %d(%d)", ssc, ssc)
	ShiftType1IE(iei, pdu)
	return
}

//-----
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

func ShiftType1IE(iei bool, pdu *[]byte) {

	if iei == true {
		*pdu = (*pdu)[1:]
		return
	}

	(*pdu)[0] >>= 4
	return
}

// TS 33.401
// A.2 KASME derivation function
/*
func (ue *UE) ComputeKasme(ck, ik []byte) {

	s := []byte{}
	fc := []byte{0x10}
	s = append(s, fc...)

	p0 := encPLMN(ue.MCC, ue.MNC)
	s = append(s, p0[:]...)
	ue.dprint("ComputeKasme: P0:%x", p0)

	l0 := []byte{0x00, 0x03}
	s = append(s, l0...)

	p1 := ue.AuthParam.seqxorak
	s = append(s, p1...)
	ue.dprint("ComputeKasme: P1:%x", p1)

	l1 := []byte{0x00, 0x06}
	s = append(s, l1...)

	k := append(ck, ik...)

	mac := hmac.New(sha256.New, k)
	mac.Write(s)
	ue.AuthParam.Kasme = mac.Sum(nil)

	return
}

// TS 33.401
// A.7 Algorithm key derivation functions
func (ue *UE) ComputeEPCAlgKey() {

	var cipher byte = 0x00
	Senc := []byte{0x15, 0x01, 0x00, 0x01, cipher, 0x00, 0x01}
	Menc := hmac.New(sha256.New, ue.AuthParam.Kasme)
	Menc.Write(Senc)
	ue.AuthParam.KencEPC = Menc.Sum(nil)

	var integrity byte = 0x02 // 128-EIA2 see TS 33.401 5.1.4.2
	Sint := []byte{0x15, 0x02, 0x00, 0x01, integrity, 0x00, 0x01}
	Mint := hmac.New(sha256.New, ue.AuthParam.Kasme)
	Mint.Write(Sint)
	ue.AuthParam.KintEPC = Mint.Sum(nil)

	// For an algorithm key of length n bits, where n is less or equal to 256,
 	// the n least significant bits of the 256 bits of the KDF output shall be
	// used as the algorithm key.

	n := len(ue.AuthParam.Kenc)
	ue.AuthParam.KencEPC = ue.AuthParam.KencEPC[n-16:]
	ue.AuthParam.KintEPC = ue.AuthParam.KintEPC[n-16:]
	return
}
*/

// TS 33.501
// A.2 KAUSF derivation function
func (ue *UE) ComputeKausf(ck, ik []byte) {

	s := []byte{}
	fc := []byte{0x6a}
	s = append(s, fc...)

	p0str := fmt.Sprintf("5G:mnc%03d.mcc%03d.3gppnetwork.org", ue.MNC, ue.MCC)
	p0 := []byte(p0str)
	s = append(s, p0...)

	l0 := make([]byte, 2)
	binary.BigEndian.PutUint16(l0, uint16(len(p0)))
	s = append(s, l0...)
	//ue.dprint("ComputeKausf: serving network(%d): %s", len(p0), p0str)

	p1 := ue.AuthParam.seqxorak
	s = append(s, p1...)

	l1 := make([]byte, 2)
	binary.BigEndian.PutUint16(l1, uint16(len(p1)))
	s = append(s, l1...)
	//ue.dprint("ComputeKausf: SEQ xor AK(%d): %x", len(p1), p1)

	k := append(ck, ik...)

	mac := hmac.New(sha256.New, k)
	mac.Write(s)
	ue.AuthParam.Kausf = mac.Sum(nil)

	return
}

// TS 33.501
// A.4 RES* and XRES* derivation function
func (ue *UE) ComputeRESstar(rand, res, ck, ik []byte) {

	s := []byte{}
	fc := []byte{0x6b}
	s = append(s, fc...)

	p0str := fmt.Sprintf("5G:mnc%03d.mcc%03d.3gppnetwork.org", ue.MNC, ue.MCC)
	p0 := []byte(p0str)
	s = append(s, p0...)

	l0 := make([]byte, 2)
	binary.BigEndian.PutUint16(l0, uint16(len(p0)))
	s = append(s, l0...)

	s = append(s, rand...)
	l1 := make([]byte, 2)
	binary.BigEndian.PutUint16(l1, uint16(len(rand)))
	s = append(s, l1...)

	s = append(s, res...)
	l2 := make([]byte, 2)
	binary.BigEndian.PutUint16(l2, uint16(len(res)))
	s = append(s, l2...)

	k := append(ck, ik...)

	mac := hmac.New(sha256.New, k)
	mac.Write(s)
	resstar := mac.Sum(nil)

	/*
	 * The (X)RES* is identified with the 128 least significant bits of the
	 * output of the KDF.
	 */
	n := len(resstar)
	ue.AuthParam.RESstar = resstar[n-16:]

	return
}

// TS 33.501
// A.6 KSEAF derivation function
func (ue *UE) ComputeKseaf() {

	s := []byte{}
	fc := []byte{0x6c}
	s = append(s, fc...)

	p0str := fmt.Sprintf("5G:mnc%03d.mcc%03d.3gppnetwork.org", ue.MNC, ue.MCC)
	p0 := []byte(p0str)
	s = append(s, p0...)

	l0 := make([]byte, 2)
	binary.BigEndian.PutUint16(l0, uint16(len(p0)))
	s = append(s, l0...)
	//ue.dprint("ComputeKseaf: serving network(%d): %s", len(p0), p0str)

	mac := hmac.New(sha256.New, ue.AuthParam.Kausf)
	mac.Write(s)
	ue.AuthParam.Kseaf = mac.Sum(nil)

	return
}

// TS 33.501
// A.7 KAMF derivation function
func (ue *UE) ComputeKamf() {

	s := []byte{}
	fc := []byte{0x6d}
	s = append(s, fc...)

	supi := fmt.Sprintf("%d%02d%s", ue.MCC, ue.MNC, ue.MSIN)
	p0 := []byte(supi)
	s = append(s, p0...)

	l0 := make([]byte, 2)
	binary.BigEndian.PutUint16(l0, uint16(len(p0)))
	s = append(s, l0...)
	//ue.dprint("ComputeKamf: supi(%d): %s", len(p0), supi)

	p1 := ue.AuthParam.abba
	s = append(s, p1...)

	l1 := make([]byte, 2)
	binary.BigEndian.PutUint16(l1, uint16(len(p1)))
	s = append(s, l1...)

	//ue.dprint("ComputeKamf: abba(%d): %x", len(p1), p1)
	//ue.dprint("ComputeKamf: S: %x", s)
	//ue.dprint("ComputeKamf: Kseaf: %x", ue.AuthParam.Kseaf)

	mac := hmac.New(sha256.New, ue.AuthParam.Kseaf)
	mac.Write(s)
	ue.AuthParam.Kamf = mac.Sum(nil)

	return
}

// TS 33.501
// A.8 Algorithm key derivation functions
func (ue *UE) ComputeAlgKey() {

	var cipher byte = 0x00
	Senc := []byte{0x69, 0x01, 0x00, 0x01, cipher, 0x00, 0x01}
	Menc := hmac.New(sha256.New, ue.AuthParam.Kamf)
	Menc.Write(Senc)
	ue.AuthParam.Kenc = Menc.Sum(nil)

	var integrity byte = 0x02 // 128-EIA2 see TS 33.401 5.1.4.2
	Sint := []byte{0x69, 0x02, 0x00, 0x01, integrity, 0x00, 0x01}
	Mint := hmac.New(sha256.New, ue.AuthParam.Kamf)
	Mint.Write(Sint)
	ue.AuthParam.Kint = Mint.Sum(nil)

	// For an algorithm key of length n bits, where n is less or equal to 256,
	// the n least significant bits of the 256 bits of the KDF output shall be
	// used as the algorithm key.
	n := len(ue.AuthParam.Kenc)
	ue.AuthParam.Kenc = ue.AuthParam.Kenc[n-16:]
	ue.AuthParam.Kint = ue.AuthParam.Kint[n-16:]
	return
}

func (ue *UE) ComputeMAC(dir uint8, pdu *[]byte) (mac []byte) {

	m := []byte{}

	tmp := make([]byte, 4)
	count := uint32((*pdu)[0])
	binary.BigEndian.PutUint32(tmp, count)
	m = append(m, tmp...)

	tmp = make([]byte, 1)
	var bearer uint8 = 1                // is the same value as free5gc v3.0.2
	tmp[0] = (bearer << 3) | (dir << 2) // bearer is 5 bit field.
	m = append(m, tmp...)
	m = append(m, []byte{0, 0, 0}...) // 24 bit padding
	m = append(m, *pdu...)

	block, _ := aes.NewCipher(ue.AuthParam.Kint)
	mac, _ = cmac.Sum(m, block, 16)
	mac = mac[:4]

	return
}

//-----
func readPduByte(pdu *[]byte) (val byte) {
	val = byte((*pdu)[0])
	*pdu = (*pdu)[1:]
	return
}

func readPduUint16(pdu *[]byte) (val uint16) {
	val = binary.BigEndian.Uint16(*pdu)
	*pdu = (*pdu)[2:]
	return
}

func readPduByteSlice(pdu *[]byte, length int) (val []byte) {
	val = (*pdu)[:length]
	*pdu = (*pdu)[length:]
	return
}

func (ue *UE) SetIndent(indent int) {
	ue.indent = indent
	return
}

func (ue *UE) SetDebugLevel(level int) {
	ue.dbgLevel = level
	return
}

func (ue *UE) dprint(format string, v ...interface{}) {
	if ue.dbgLevel == 0 {
		return
	}
	indent := strings.Repeat("  ", ue.indent)
	fmt.Printf(indent+format+"\n", v...)
	return
}

func (ue *UE) dprinti(format string, v ...interface{}) {
	ue.indent++
	ue.dprint(format, v...)
	ue.indent--
}
