package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	RequestLength   = 37
	SignatureLength = 96 // Hopper/Blackwell/LS10 P-384 ECDSA raw r||s
)

type Request struct {
	Version byte
	Code    byte
	Param1  byte
	Param2  byte
	Nonce   []byte
	SlotID  byte
}

type Response struct {
	Version                 byte
	Code                    byte
	Param1                  byte
	Param2                  byte
	MeasurementBlockCount   byte
	MeasurementRecordLength int
	MeasurementRecord       []byte
	Nonce                   []byte
	OpaqueFields            map[uint16][]byte
	OpaqueLength            int
	Signature               []byte
}

type Quote struct {
	Raw      []byte
	Request  Request
	Response Response
}

func ParseQuote(raw []byte) (*Quote, error) {
	if len(raw) <= RequestLength+SignatureLength {
		return nil, fmt.Errorf("quote too short: got %d bytes", len(raw))
	}

	q := &Quote{Raw: raw}
	requestRaw := raw[:RequestLength]
	responseRaw := raw[RequestLength:]

	q.Request = Request{
		Version: requestRaw[0],
		Code:    requestRaw[1],
		Param1:  requestRaw[2],
		Param2:  requestRaw[3],
		Nonce:   append([]byte(nil), requestRaw[4:36]...),
		SlotID:  requestRaw[36],
	}

	if len(responseRaw) < 8+32+2+SignatureLength {
		return nil, fmt.Errorf("response section too short: got %d bytes", len(responseRaw))
	}
	byteIndex := 0
	measurementRecordLength := int(ReadLE(responseRaw[5:8]))
	byteIndex = 8
	if len(responseRaw) < byteIndex+measurementRecordLength+32+2+SignatureLength {
		return nil, fmt.Errorf("response lengths are inconsistent with total size")
	}
	measurementRecord := append([]byte(nil), responseRaw[byteIndex:byteIndex+measurementRecordLength]...)
	byteIndex += measurementRecordLength
	responseNonce := append([]byte(nil), responseRaw[byteIndex:byteIndex+32]...)
	byteIndex += 32
	opaqueLength := int(ReadLE(responseRaw[byteIndex : byteIndex+2]))
	byteIndex += 2
	if len(responseRaw) < byteIndex+opaqueLength+SignatureLength {
		return nil, fmt.Errorf("opaque length exceeds response size")
	}
	opaqueRaw := responseRaw[byteIndex : byteIndex+opaqueLength]
	byteIndex += opaqueLength
	signature := append([]byte(nil), responseRaw[byteIndex:]...)
	if len(signature) != SignatureLength {
		return nil, fmt.Errorf("unexpected signature length: got %d, want %d", len(signature), SignatureLength)
	}

	opaqueFields, err := ParseOpaqueFields(opaqueRaw)
	if err != nil {
		return nil, err
	}

	q.Response = Response{
		Version:                 responseRaw[0],
		Code:                    responseRaw[1],
		Param1:                  responseRaw[2],
		Param2:                  responseRaw[3],
		MeasurementBlockCount:   responseRaw[4],
		MeasurementRecordLength: measurementRecordLength,
		MeasurementRecord:       measurementRecord,
		Nonce:                   responseNonce,
		OpaqueFields:            opaqueFields,
		OpaqueLength:            opaqueLength,
		Signature:               signature,
	}

	return q, nil
}

func ParseOpaqueFields(raw []byte) (map[uint16][]byte, error) {
	fields := make(map[uint16][]byte)
	for i := 0; i < len(raw); {
		if len(raw[i:]) < 4 {
			return nil, errors.New("opaque data truncated")
		}
		fieldType := uint16(ReadLE(raw[i : i+2]))
		i += 2
		size := int(ReadLE(raw[i : i+2]))
		i += 2
		if len(raw[i:]) < size {
			return nil, fmt.Errorf("opaque field %d truncated", fieldType)
		}
		fields[fieldType] = append([]byte(nil), raw[i:i+size]...)
		i += size
	}
	return fields, nil
}

func (r Response) GetMeasurements() []string {
	record := r.MeasurementRecord
	count := int(r.MeasurementBlockCount)
	measurements := make([]string, count)
	for i := 0; i < len(record); {
		if len(record[i:]) < 4 {
			break
		}
		idx := int(record[i])
		i++
		_ = record[i]
		i++
		size := int(ReadLE(record[i : i+2]))
		i += 2
		if len(record[i:]) < size {
			break
		}
		block := record[i : i+size]
		i += size
		if len(block) < 3 || idx <= 0 || idx > count {
			continue
		}
		valSize := int(ReadLE(block[1:3]))
		if len(block) < 3+valSize {
			continue
		}
		measurements[idx-1] = hex.EncodeToString(block[3 : 3+valSize])
	}
	return measurements
}

func DecodeHexOrRaw(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty input")
	}

	withoutWhitespace := make([]byte, 0, len(data))
	hexCandidate := true
	for _, b := range data {
		if b == ' ' || b == '\n' || b == '\r' || b == '\t' {
			continue
		}
		if !IsHex([]byte{b}) {
			hexCandidate = false
			break
		}
		withoutWhitespace = append(withoutWhitespace, b)
	}
	if hexCandidate {
		if len(withoutWhitespace) == 0 {
			return nil, errors.New("empty input")
		}
		if len(withoutWhitespace)%2 != 0 {
			return nil, errors.New("hex input has odd length")
		}
		decoded := make([]byte, hex.DecodedLen(len(withoutWhitespace)))
		if _, err := hex.Decode(decoded, withoutWhitespace); err != nil {
			return nil, err
		}
		return decoded, nil
	}
	return append([]byte(nil), data...), nil
}

func IsHex(data []byte) bool {
	for _, b := range data {
		switch {
		case b >= '0' && b <= '9':
		case b >= 'a' && b <= 'f':
		case b >= 'A' && b <= 'F':
		default:
			return false
		}
	}
	return true
}

func ReadLE(data []byte) uint64 {
	var v uint64
	for i := len(data) - 1; i >= 0; i-- {
		v = (v << 8) | uint64(data[i])
		if i == 0 {
			break
		}
	}
	return v
}

func DecodeCString(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	data = bytes.TrimRight(data, "\x00")
	return string(data)
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
