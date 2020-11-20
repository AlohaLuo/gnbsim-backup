// Copyright 2020 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

// Package gtp is implementation for GTPv1-U in the 5GS Sytem.
// document version: 3GPP TS 29.281 v16.1.0 (2020-09)

package gtp

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	Port = 2152
)

type GTP struct {
	IFname    string
	LocalAddr net.IP
	PeerAddr  net.IP
	LocalTEID uint32
	PeerTEID  uint32
	QosFlowID uint8
	HasExtensionHeader bool
}

func NewGTP(lteid uint32, pteid uint32) (p *GTP) {

	var gtp GTP
	gtp.LocalTEID = lteid
	gtp.PeerTEID = pteid

	p = &gtp
	return
}

func (gtp *GTP) SetQosFlowID(id uint8) {
	gtp.QosFlowID = id
	return
}

func (gtp *GTP) SetExtensionHeader(flag bool) {
	gtp.HasExtensionHeader = flag
	return
}

// 5 GTP-U header
// 5.1 General format
const (
	gtpuVersion = 0x20
	protocolTypeGTP = 0x10
	protocolTypeGTPprime = 0x00
	hasExtensionHeader = 0x04
)

func (gtp *GTP) encGTPHeader(payloadLen int) (pdu []byte) {

	var versAndFlags uint8
	versAndFlags |= gtpuVersion
	versAndFlags |= protocolTypeGTP

	extHeaders := []uint8{}
	if gtp.HasExtensionHeader {
		versAndFlags |= hasExtensionHeader
		extHeaders = append(extHeaders,
			extHeaderTypePDUSessionContainer)
	}
	pdu = append(pdu, versAndFlags)

	var messageType uint8 = 0xff // T-PDU
	pdu = append(pdu, messageType)

	extHead := []byte{}
	extHeaders = append(extHeaders, extHeaderTypeNone)
	for _, extType := range extHeaders {
		extHead = append(extHead, gtp.encExtensionHeader(extType)...)
	}

	if gtp.HasExtensionHeader {
		padding := make([]byte, 3) // Sequence Number and N-PDU Number
		extHead = append(padding, extHead...)
	}

	gtpLen := payloadLen + len(extHead)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(gtpLen))
	pdu = append(pdu, length...)

	teid := make([]byte, 4)
	binary.BigEndian.PutUint32(teid, gtp.PeerTEID)
	pdu = append(pdu, teid...)
	pdu = append(pdu, extHead...)

	return
}

func (gtp *GTP) decGTPHeader(payload []byte) (raw []byte) {

	versAndFlags := readPayloadByte(&payload)

	if (versAndFlags & hasExtensionHeader) == 0 {
		raw = payload[7:]
		return
	}
	raw = payload[15:]
	return
}

// 5.2 GTP-U Extension Header
// 5.2.1 General format of the GTP-U Extension Header
const (
	extHeaderTypeNone                = 0x00
	extHeaderTypePDUSessionContainer = 0x85
)

func (gtp *GTP) encExtensionHeader(extHeaderType uint8) (pdu []byte) {

	var content []byte

	switch extHeaderType {
	case extHeaderTypeNone:
		pdu = append(pdu, extHeaderType)
		return
	case extHeaderTypePDUSessionContainer:
		content = gtp.encULPduSessionInformation()
	default:
		fmt.Printf("unknown extension header type.")
		return
	}
	pdu = append(pdu, extHeaderType)

	length := len(content)
	if length%4 != 2 {
		fmt.Printf("invalid extension header length=%d.", length)
		return
	}

	length = (len(content) + 2) / 4
	pdu = append(pdu, uint8(length))
	pdu = append(pdu, content...)

	return
}

// 5.2.2.7 PDU Session Container
// 5.5.2.2 UL PDU SESSION INFORMATION (PDU Type 1) in TS 38.415
const (
	pduTypeDL = iota
	pduTypeUL
)

type ULPduSessionInformation struct {
	pduTypeAndFlags   uint8
	qosFlowIdentifier uint8
}

func (gtp *GTP) encULPduSessionInformation() (pdu []byte) {

	var pduTypeAndFlags uint8
	pduTypeAndFlags = pduTypeUL << 4

	pdu = append([]byte{}, pduTypeAndFlags)
	pdu = append(pdu, gtp.QosFlowID)

	return
}

func (gtp *GTP) Encap(raw []byte) (payload []byte) {
	length := len(raw)
	payload = append(payload, gtp.encGTPHeader(length)...)
	payload = append(payload, raw...)
	return
}

func (gtp *GTP) Decap(payload []byte) (raw []byte) {
	raw = gtp.decGTPHeader(payload)
	return
}
//-----
func readPayloadByte(payload *[]byte) (val byte) {
	val = byte((*payload)[0])
	*payload = (*payload)[1:]
	return
}

func readPayloadUint16(payload *[]byte) (val uint16) {
	val = binary.BigEndian.Uint16(*payload)
	*payload = (*payload)[2:]
	return
}

func readPayloadUint32(payload *[]byte) (val uint32) {
	val = binary.BigEndian.Uint32(*payload)
	*payload = (*payload)[4:]
	return
}

func readPayloadByteSlice(payload *[]byte, length int) (val []byte) {
	val = (*payload)[:length]
	*payload = (*payload)[length:]
	return
}


