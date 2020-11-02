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
}

func NewGTP() (p *GTP) {

	var gtp GTP
	p = &gtp

	return
}

// 5 GTP-U header
// 5.1 General format
func (gtp *GTP) encGTPHeader(payloadLen int) (pdu []byte) {

	var versAndFlags uint8
	var version uint8 = 1
	versAndFlags = version << 5
	var pt uint8 = 1 // GTP:1, GTP':0
	versAndFlags |= pt << 4

	extHeaders := []uint8{}
	if gtp.QosFlowID != 0 {
		var hasExtensionHeader uint8 = 1
		versAndFlags |= hasExtensionHeader << 2
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
		fmt.Errorf("unknown extension header type.")
		return
	}

	pdu = append(pdu, extHeaderType)

	length := len(pdu)
	if length%4 != 2 {
		fmt.Errorf("invalid extension header length=%d.", length)
		return
	}

	length = (len(pdu) + 2) / 4
	pdu = append(pdu, uint8(length))
	pdu = append(pdu, content...)

	return
}

// 5.2.2.7 PDU Session Container
// 5.5.2.2 UL PDU SESSION INFORMATION (PDU Type 1) in TS 38.415
const (
	pduTypeDL = iota
	pduTypeUL = iota
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

func (gtp *GTP) Encap(pdu *[]byte) {
	return
}

func (gtp *GTP) Decap(pdu *[]byte) {
	return
}
