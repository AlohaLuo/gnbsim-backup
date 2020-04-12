// Copyright 2019-2020 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

// Package ngap is implementation for NG Application Protocol (NGAP)
// in the 5GS Sytem.
// document version: 3GPP TS 38.413 v16.0.0 (2019-12)
package ngap

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/bits"
	"strconv"

	"github.com/hhorai/gnbsim/encoding/nas"
	"github.com/hhorai/gnbsim/encoding/per"
)

const (
	reject = iota
	ignore
	notify
)

const (
	initiatingMessage = iota
	sucessfulOutcome
	unsuccessfulOutcome
)

// Elementary Procedures constants
const (
	idInitialUEMessage = 15
	idNGSetup          = 21
)

const (
	idDefaultPagingDRX        = 21
	idGlobalRANNodeID         = 27
	idNASPDU                  = 38
	idRANUENGAPID             = 85
	idRRCEstablishmentCause   = 90
	idSupportedTAList         = 102
	idUEContextRequest        = 112
	idUserLocationInformation = 121
)

type GNB struct {
	GlobalGNBID     GlobalGNBID
	SupportedTAList []SupportedTA
	PagingDRX       string
	RANUENGAPID     uint32
	UE              nas.UE
	ULInfoNR        UserLocationInformationNR
}

func NewNGAP(filename string) (p *GNB) {

	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	var gnb GNB
	p = &gnb
	json.Unmarshal(bytes, p)

	return
}

// 9.2.5.1 INITIAL UE MESSAGE
/*
InitialUEMessage ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container        { {InitialUEMessage-IEs} },
    ...
}

InitialUEMessage-IEs NGAP-PROTOCOL-IES ::= {
    { ID id-RAN-UE-NGAP-ID              CRITICALITY reject  TYPE RAN-UE-NGAP-ID             PRESENCE mandatory  }|
    { ID id-NAS-PDU                     CRITICALITY reject  TYPE NAS-PDU                    PRESENCE mandatory  }|
    { ID id-UserLocationInformation     CRITICALITY reject  TYPE UserLocationInformation    PRESENCE mandatory  }|
    { ID id-RRCEstablishmentCause       CRITICALITY ignore  TYPE RRCEstablishmentCause      PRESENCE mandatory  }|
    { ID id-FiveG-S-TMSI                CRITICALITY reject  TYPE FiveG-S-TMSI               PRESENCE optional   }|
    { ID id-AMFSetID                    CRITICALITY ignore  TYPE AMFSetID                   PRESENCE optional   }|
    { ID id-UEContextRequest            CRITICALITY ignore  TYPE UEContextRequest           PRESENCE optional   }|
    { ID id-AllowedNSSAI                CRITICALITY reject  TYPE AllowedNSSAI               PRESENCE optional   },
    ...
}
*/
func (gnb *GNB) MakeInitialUEMessage() (pdu []byte) {

	pdu = encNgapPdu(initiatingMessage, idInitialUEMessage, ignore)
	fmt.Printf("debug: pdu = %02x\n", pdu)

	v := encProtocolIEContainer(4)
	fmt.Printf("debug: ie container = %02x\n", v)

	tmp := encRANUENGAPID(gnb.RANUENGAPID)
	fmt.Printf("debug: global RAN-UE-NGAP-ID = %02x\n", tmp)
	v = append(v, tmp...)

	tmp = encNASPDU(gnb.UE.MakeRegistrationRequest())
	fmt.Printf("debug: 5G NAS PDU = %02x\n", tmp)
	v = append(v, tmp...)

	tmp, _ = gnb.encUserLocationInformation()
	fmt.Printf("debug: User Location Information = %02x\n", tmp)
	v = append(v, tmp...)

	tmp, _ = gnb.encRRCEstablishmentCause(rrcMoSignalling)
	fmt.Printf("debug: RRC Establishment Cause = %02x\n", tmp)
	v = append(v, tmp...)

	tmp, _ = gnb.encUEContextRequest()
	fmt.Printf("debug: UE Context Request = %02x\n", tmp)
	v = append(v, tmp...)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)

	pdu = append(pdu, length...)
	pdu = append(pdu, v...)

	return
}

// 9.2.6.1 NG SETUP REQUEST
/*
NGSetupRequest ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container        { {NGSetupRequestIEs} },
    ...
}

NGSetupRequestIEs NGAP-PROTOCOL-IES ::= {
    { ID id-GlobalRANNodeID         CRITICALITY reject  TYPE GlobalRANNodeID            PRESENCE mandatory  }|
    { ID id-RANNodeName             CRITICALITY ignore  TYPE RANNodeName                PRESENCE optional}|
    { ID id-SupportedTAList         CRITICALITY reject  TYPE SupportedTAList            PRESENCE mandatory  }|
    { ID id-DefaultPagingDRX        CRITICALITY ignore  TYPE PagingDRX                  PRESENCE mandatory  }|
    { ID id-UERetentionInformation  CRITICALITY ignore  TYPE UERetentionInformation     PRESENCE optional   },
    ...
}
*/
func (gnb *GNB) MakeNGSetupRequest() (pdu []byte) {

	pdu = encNgapPdu(initiatingMessage, idNGSetup, reject)
	fmt.Printf("debug: pdu = %02x\n", pdu)

	v := encProtocolIEContainer(3)
	fmt.Printf("debug: ie container = %02x\n", v)

	tmp, _ := gnb.encGlobalRANNodeID(&gnb.GlobalGNBID)
	fmt.Printf("debug: global RAN Node ID = %02x\n", tmp)
	v = append(v, tmp...)

	tmp, _ = gnb.encSupportedTAList(&gnb.SupportedTAList)
	fmt.Printf("debug: Supported TA List = %02x\n", tmp)
	v = append(v, tmp...)

	tmp, _ = encPagingDRX(gnb.PagingDRX)
	fmt.Printf("debug: PagingDRX = %02x\n", tmp)
	v = append(v, tmp...)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)

	pdu = append(pdu, length...)
	pdu = append(pdu, v...)

	return
}

/*
NGAP-PDU ::= CHOICE {
    initiatingMessage           InitiatingMessage,
    successfulOutcome           SuccessfulOutcome,
    unsuccessfulOutcome         UnsuccessfulOutcome,
    ...
}
ProcedureCode ::= INTEGER (0..255)
Criticality   ::= ENUMERATED { reject, ignore, notify }

InitiatingMessage ::= SEQUENCE {
    procedureCode   NGAP-ELEMENTARY-PROCEDURE.&procedureCode        ({NGAP-ELEMENTARY-PROCEDURES}),
    criticality     NGAP-ELEMENTARY-PROCEDURE.&criticality          ({NGAP-ELEMENTARY-PROCEDURES}{@procedureCode}),
    value           NGAP-ELEMENTARY-PROCEDURE.&InitiatingMessage    ({NGAP-ELEMENTARY-PROCEDURES}{@procedureCode})
}
*/
func encNgapPdu(pduType int, procCode int64, criticality uint) (pdu []byte) {
	pdu, _, _ = per.EncChoice(pduType, 0, 2, true)
	v, _, _ := per.EncInteger(procCode, 0, 255, false)
	pdu = append(pdu, v...)
	v, _, _ = per.EncEnumerated(criticality, 0, 2, false)
	pdu = append(pdu, v...)

	return
}

/*
NGSetupRequest ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container        { {NGSetupRequestIEs} },
    ...
}
ProtocolIE-Container {NGAP-PROTOCOL-IES : IEsSetParam} ::=
    SEQUENCE (SIZE (0..maxProtocolIEs)) OF
    ProtocolIE-Field {{IEsSetParam}}

maxProtocolIEs                          INTEGER ::= 65535
*/
func encProtocolIEContainer(num uint) (container []byte) {
	const maxProtocolIEs = 65535
	container, _, _ = per.EncSequence(true, 0, 0)
	v, _, _ := per.EncSequenceOf(num, 0, maxProtocolIEs, false)
	container = append(container, v...)

	return
}

func encProtocolIE(id int64, criticality uint) (v []byte, err error) {

	v1, _, _ := per.EncInteger(id, 0, 65535, false)
	v2, _, _ := per.EncEnumerated(criticality, 0, 2, false)
	v = append(v1, v2...)

	return
}

// 9.3.1.5 Global RAN Node ID
/*
  It returns only GNB-ID for now.
   GlobalRANNodeID ::= CHOICE {
       globalGNB-ID        GlobalGNB-ID,
       globalNgENB-ID      GlobalNgENB-ID,
       globalN3IWF-ID      GlobalN3IWF-ID,
       choice-Extensions   ProtocolIE-SingleContainer { {GlobalRANNodeID-ExtIEs} }
   }
*/
const (
	globalGNB = iota
	globalNgGNB
	globalN3IWF
)

func (gnb *GNB) encGlobalRANNodeID(p *GlobalGNBID) (v []byte, err error) {

	head, err := encProtocolIE(idGlobalRANNodeID, reject)

	// NG-ENB and N3IWF are not implemented yet...
	pv, plen, _ := per.EncChoice(globalGNB, 0, 2, false)
	pv2, plen2, v2 := gnb.encGlobalGNBID(p)
	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)
	pv = append(pv, v2...)

	length, _, _ := per.EncLengthDeterminant(len(pv), 0)
	head = append(head, length...)
	v = append(head, pv...)

	return
}

// 9.3.1.6 Global gNB ID
/*
   GlobalGNB-ID ::= SEQUENCE {
       pLMNIdentity        PLMNIdentity,
       gNB-ID              GNB-ID,
       iE-Extensions       ProtocolExtensionContainer { {GlobalGNB-ID-ExtIEs} } OPTIONAL,
       ...
   }
*/
type GlobalGNBID struct {
	MCC   uint16
	MNC   uint16
	GNBID uint32
}

func (gnb *GNB) encGlobalGNBID(p *GlobalGNBID) (pv []byte, plen int, v []byte) {

	pv, plen, _ = per.EncSequence(true, 1, 0)
	v = append(v, gnb.encPLMNIdentity(p.MCC, p.MNC)...)

	pv2, _ := encGNBID(p.GNBID)
	v = append(v, pv2...)
	return
}

/*
   GNB-ID ::= CHOICE {
       gNB-ID                  BIT STRING (SIZE(22..32)),
       choice-Extensions       ProtocolIE-SingleContainer { {GNB-ID-ExtIEs} }
   }
*/
const (
	minGNBIDSize = 22
	maxGNBIDSize = 32
)

func encGNBID(gnbid uint32) (pv []byte, plen int) {

	bitlen := bits.Len32(gnbid)
	if bitlen < minGNBIDSize {
		bitlen = minGNBIDSize
	}

	pv, plen, _ = per.EncChoice(0, 0, 1, false)

	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, gnbid)
	pv2, plen2, v, _ := per.EncBitString(tmp, bitlen,
		minGNBIDSize, maxGNBIDSize, false)

	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)
	pv = append(pv, v...)

	return
}

// 9.3.1.7 NR CGI
/*
NR-CGI ::= SEQUENCE {
    pLMNIdentity        PLMNIdentity,
    nRCellIdentity      NRCellIdentity,
    iE-Extensions       ProtocolExtensionContainer { {NR-CGI-ExtIEs} } OPTIONAL,
    ...
}
NRCellIdentity ::= BIT STRING (SIZE(36))
*/
type NRCGI struct {
	PLMN     PLMN
	NRCellID uint64
}

const (
	nrCellIDSize = 36
)

func (gnb *GNB) encNRCGI(nrcgi *NRCGI) (pv []byte, plen int, v []byte,
	err error) {

	pv, plen, _ = per.EncSequence(true, 1, 0)
	v = gnb.encPLMNIdentity(nrcgi.PLMN.MCC, nrcgi.PLMN.MNC)
	v = append(v, gnb.encNRCellIdentity(nrcgi.NRCellID)...)

	return
}

func (gnb *GNB) encNRCellIdentity(cellid uint64) (v []byte) {

	// The leftmost bits of the NR Cell Identity IE correspond to the gNB ID
	// (defined in subclause 9.3.1.6).
	gnbid := gnb.GlobalGNBID.GNBID
	gnbidlen := bits.Len32(gnbid)

	if gnbidlen < minGNBIDSize {
		gnbidlen = minGNBIDSize
	}

	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, gnbid)
	pv, plen := per.ShiftLeftMost(tmp, gnbidlen)

	cellidlen := nrCellIDSize - gnbidlen
	tmp = make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, cellid)
	pv2, plen2 := per.ShiftLeftMost(tmp, cellidlen)

	v, _ = per.MergeBitField(pv, plen, pv2, plen2)

	return
}

// 9.3.1.16 User Location Information
/*
UserLocationInformation ::= CHOICE {
    userLocationInformationEUTRA    UserLocationInformationEUTRA,
    userLocationInformationNR       UserLocationInformationNR,
    userLocationInformationN3IWF    UserLocationInformationN3IWF,
    choice-Extensions       ProtocolIE-SingleContainer { {UserLocationInformation-ExtIEs} }
}
*/
const (
	ULInfoEUTRA = iota
	ULInfoNR
	ULInfoN3IWF
)

func (gnb *GNB) encUserLocationInformation() (v []byte, err error) {
	head, err := encProtocolIE(idUserLocationInformation, reject)

	// NG-ENB and N3IWF are not implemented yet...
	pv, plen, _ := per.EncChoice(ULInfoNR, 0, 2, false)

	pv2, plen2, v := gnb.encUserLocationInformationNR(&gnb.ULInfoNR)
	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)

	pv = append(pv, v...)

	length, _, _ := per.EncLengthDeterminant(len(pv), 0)
	head = append(head, length...)
	v = append(head, pv...)

	return
}

/*
UserLocationInformationNR ::= SEQUENCE {
    nR-CGI              NR-CGI,
    tAI                 TAI,
    timeStamp           TimeStamp                                                           OPTIONAL,
    iE-Extensions       ProtocolExtensionContainer { {UserLocationInformationNR-ExtIEs} }   OPTIONAL,
    ...
}
*/
type UserLocationInformationNR struct {
	NRCGI NRCGI
	TAI   TAI
}

func (gnb *GNB) encUserLocationInformationNR(info *UserLocationInformationNR) (pv []byte, plen int, v []byte) {
	pv, plen, _ = per.EncSequence(true, 2, 0)
	pv2, plen2, v, _ := gnb.encNRCGI(&info.NRCGI)
	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)

	pv2, plen2, v2, _ := gnb.encTAI(&info.TAI)
	v = append(v, pv2...)
	v = append(v, v2...)

	return
}

// 9.3.1.90 PagingDRX
/*
PagingDRX ::= ENUMERATED {
    v32,
    v64,
    v128,
    v256,
    ...
}
*/
func encPagingDRX(drx string) (v []byte, err error) {

	head, err := encProtocolIE(idDefaultPagingDRX, ignore)

	var n uint = 0

	switch drx {
	case "v32":
		n = 0
	case "v64":
		n = 1
	case "v128":
		n = 2
	case "v256":
		n = 3
	default:
		fmt.Printf("encPagingDRX: no such DRX value(%s)\n", drx)
		return
	}
	pv, _, _ := per.EncEnumerated(n, 0, 3, true)

	length, _, _ := per.EncLengthDeterminant(len(pv), 0)
	head = append(head, length...)
	v = append(head, pv...)

	return
}

// 9.3.3.5 PLMN Identity
/*
PLMNIdentity ::= OCTET STRING (SIZE(3))
*/
type PLMN struct {
	MCC uint16
	MNC uint16
}

func (gnb *GNB) encPLMNIdentity(mcc, mnc uint16) (v []byte) {

	v = make([]byte, 3, 3)
	v[0] = byte(mcc % 1000 / 100)
	v[0] |= byte(mcc%100/10) << 4

	v[1] = byte(mcc % 10)
	v[1] |= 0xf0 // filler digit

	v[2] = byte(mnc % 100 / 10)
	v[2] |= byte(mnc%10) << 4

	_, _, v, _ = per.EncOctetString(v, 3, 3, false)

	return
}

/*
SliceSupportList ::= SEQUENCE (SIZE(1..maxnoofSliceItems)) OF SliceSupportItem
    maxnoofSliceItems                   INTEGER ::= 1024
*/
func encSliceSupportList(p *[]SliceSupport) (v []byte) {
	v, _, _ = per.EncSequenceOf(1, 1, 1024, false)
	for _, item := range *p {
		v = append(v, encSliceSupportItem(&item)...)
	}
	return
}

/*
SliceSupportItem ::= SEQUENCE {
    s-NSSAI             S-NSSAI,
    iE-Extensions       ProtocolExtensionContainer { {SliceSupportItem-ExtIEs} }    OPTIONAL,
    ...
}
*/
type SliceSupport struct {
	SST uint8
	SD  string
}

func encSliceSupportItem(p *SliceSupport) (v []byte) {
	/*
		ex.1
		    .    .   .          .    .   .    .   .    .   .
		00 000 00000001	00 010 00000010 00000000 00000011 00001000
		0000 0000 0000 1xxx
		                000 1000 0000 10xx xxxx 00000000 00000011 11101000
		0x00 0x08 0x80 0x80 0x00 0x03 0xe1

		ex.2
		    .    .   .    .        .        .        .
		00 010 00000001 xxx 00000000 00000000 01111011
		0001 0000 0000 1xxx 00000000 00000000 11101000
		0x10 0x08 0x80 0x00 0x00 0x7b
	*/
	pv, plen, _ := per.EncSequence(true, 1, 0)

	pv2, plen2, v := encSNSSAI(p.SST, p.SD)
	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)
	v = append(pv, v...)
	return
}

// 9.3.1.24 S-NSSAI
/*
S-NSSAI ::= SEQUENCE {
    sST           SST,
    sD            SD                                                  OPTIONAL,
    iE-Extensions ProtocolExtensionContainer { { S-NSSAI-ExtIEs} }    OPTIONAL,
    ...
}

SST ::= OCTET STRING (SIZE(1))
SD ::= OCTET STRING (SIZE(3))
*/
func encSNSSAI(sstInt uint8, sdString string) (pv []byte, plen int, v []byte) {
	pv, plen, _ = per.EncSequence(true, 2, 0x02)

	sst := []byte{byte(sstInt)}
	pv2, plen2, _, _ := per.EncOctetString(sst, 1, 1, false)

	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)

	tmp, _ := strconv.ParseUint(sdString, 0, 32)
	sd := make([]byte, 8)
	binary.BigEndian.PutUint64(sd, tmp)
	sd = sd[len(sd)-3:]
	_, _, v, _ = per.EncOctetString(sd, 3, 3, false)
	return
}

// 9.3.1.111 RRC Establishment Cause
/*
RRCEstablishmentCause ::= ENUMERATED {
    emergency,
    highPriorityAccess,
    mt-Access,
    mo-Signalling,
    mo-Data,
    mo-VoiceCall,
    mo-VideoCall,
    mo-SMS,
    mps-PriorityAccess,
    mcs-PriorityAccess,
    ...,
    notAvailable
}
*/
const (
	rrcEmergency = iota
	rrcHighPriorityAccess
	rrcMtAccess
	rrcMoSignalling
	rrcMoData
	rrcMoVoiceCall
	rrcMoVideoCall
	rrcMoSMS
	rrcMpsPriorityAccess
	rrcMcsPriorityAccess
)

func (gnb *GNB) encRRCEstablishmentCause(cause uint) (v []byte, err error) {

	head, err := encProtocolIE(idRRCEstablishmentCause, ignore)

	/*
	 * I couldn't find the max value for the Establishment Cause.
	 * Wireshark does parse it as 4 bit field. It means that the number is
	 * from 7 to 14.
	 */
	v, _, _ = per.EncEnumerated(cause, 0, 14, true)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)
	head = append(head, length...)
	v = append(head, v...)
	return
}

// 9.3.3.2 RAN UE NGAP ID
/*
RAN-UE-NGAP-ID ::= INTEGER (0..4294967295)
*/
func encRANUENGAPID(id uint32) (v []byte) {
	head, _ := encProtocolIE(idRANUENGAPID, reject)
	v, _, _ = per.EncInteger(int64(id), 0, 4294967295, false)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)
	head = append(head, length...)
	v = append(head, v...)
	return
}

// 9.3.3.4 NAS-PDU
/*
NAS-PDU ::= OCTET STRING
*/
func encNASPDU(pdu []byte) (v []byte) {

	head, _ := encProtocolIE(idNASPDU, reject)

	pv, _, v, _ := per.EncOctetString(pdu, 0, 0, false)
	v = append(pv, v...)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)
	head = append(head, length...)
	v = append(head, v...)
	return
}

// 9.3.3.10 TAC
/*
TAC ::= OCTET STRING (SIZE(3))
*/
func (gnb *GNB) encTAC(tacString string) (v []byte) {
	const tacSize = 3
	tmp, _ := strconv.ParseUint(tacString, 0, 32)
	tac := make([]byte, 8)
	binary.BigEndian.PutUint64(tac, tmp)
	tac = tac[len(tac)-3:]

	_, _, v, _ = per.EncOctetString(tac, tacSize, tacSize, false)
	return
}

// 9.3.3.11 TAI
/*
TAI ::= SEQUENCE {
    pLMNIdentity        PLMNIdentity,
    tAC                 TAC,
    iE-Extensions       ProtocolExtensionContainer { {TAI-ExtIEs} } OPTIONAL,
    ...
}
*/
type TAI struct {
	PLMN PLMN
	TAC  string
}

func (gnb *GNB) encTAI(tai *TAI) (pv []byte, plen int, v []byte, err error) {
	pv, plen, _ = per.EncSequence(true, 1, 0)
	v = gnb.encPLMNIdentity(tai.PLMN.MCC, tai.PLMN.MNC)
	v = append(v, gnb.encTAC(tai.TAC)...)
	return
}

/*
 * following IEs/Group Names are defined in each message definitions in 9.2.
 * alphabetical order
 */

// Broadcast PLMN List is defined in 9.2.6.1 NG SETUP REQUEST
/*
BroadcastPLMNList ::= SEQUENCE (SIZE(1..maxnoofBPLMNs)) OF BroadcastPLMNItem
    maxnoofBPLMNs                       INTEGER ::= 12
*/
func (gnb *GNB) encBroadcastPLMNList(p *[]BroadcastPLMN) (v []byte) {
	const maxnoofBPLMNs = 12
	pv, plen, _ := per.EncSequenceOf(1, 1, maxnoofBPLMNs, false)

	for _, item := range *p {
		pv2, plen2, v2 := gnb.encBroadcastPLMNItem(&item)
		if plen != 0 {
			pv, _ = per.MergeBitField(pv, plen, pv2, plen2)
		}
		v = append(v, pv...)
		v = append(v, v2...)
		plen = 0
	}
	return
}

// Broadcast PLMN Item is defined in 9.2.6.1 NG SETUP REQUEST
/*
BroadcastPLMNItem ::= SEQUENCE {
    pLMNIdentity            PLMNIdentity,
    tAISliceSupportList     SliceSupportList,
    iE-Extensions           ProtocolExtensionContainer { {BroadcastPLMNItem-ExtIEs} } OPTIONAL,
    ...
}
*/
type BroadcastPLMN struct {
	MCC              uint16
	MNC              uint16
	SliceSupportList []SliceSupport
}

func (gnb *GNB) encBroadcastPLMNItem(p *BroadcastPLMN) (pv []byte, plen int, v []byte) {
	pv, plen, _ = per.EncSequence(true, 1, 0)
	v = append(v, gnb.encPLMNIdentity(p.MCC, p.MNC)...)
	v = append(v, encSliceSupportList(&p.SliceSupportList)...)
	return
}

// Supported TA List is defined in 9.2.6.1 NG SETUP REQUEST
/*
SupportedTAList ::= SEQUENCE (SIZE(1..maxnoofTACs)) OF SupportedTAItem
maxnoofTACs INTEGER ::= 256
*/
func (gnb *GNB) encSupportedTAList(p *[]SupportedTA) (v []byte, err error) {

	head, err := encProtocolIE(idSupportedTAList, reject)

	const maxnoofTACs = 256
	v, _, _ = per.EncSequenceOf(1, 1, maxnoofTACs, false)

	for _, item := range *p {
		v = append(v, gnb.encSupportedTAItem(&item)...)
	}

	length, _, _ := per.EncLengthDeterminant(len(v), 0)
	head = append(head, length...)
	v = append(head, v...)

	return
}

// Supported TA Item is defined in 9.2.6.1 NG SETUP REQUEST
/*
SupportedTAItem ::= SEQUENCE {
    tAC                     TAC,
    broadcastPLMNList       BroadcastPLMNList,
    iE-Extensions           ProtocolExtensionContainer { {SupportedTAItem-ExtIEs} } OPTIONAL,
    ...
}
*/
type SupportedTA struct {
	TAC               string
	BroadcastPLMNList []BroadcastPLMN
}

func (gnb *GNB) encSupportedTAItem(p *SupportedTA) (v []byte) {

	pv, _, _ := per.EncSequence(true, 1, 0)
	v = append(pv, gnb.encTAC(p.TAC)...)
	v = append(v, gnb.encBroadcastPLMNList(&p.BroadcastPLMNList)...)
	return
}

// UE Context Request is defined in 9.2.5.1 INITIAL UE MESSAGE
/*
UEContextRequest ::= ENUMERATED {requested, ...}
*/
func (gnb *GNB) encUEContextRequest() (v []byte, err error) {

	head, err := encProtocolIE(idUEContextRequest, ignore)

	v, _, _ = per.EncEnumerated(0, 0, 0, true)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)
	head = append(head, length...)
	v = append(head, v...)
	return
}
