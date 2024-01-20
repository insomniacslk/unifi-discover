package unifidiscover

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/insomniacslk/xjson"
	log "github.com/sirupsen/logrus"
)

var (
	DiscoveryHeader = []byte{0x01, 0x00, 0x00}
)

const (
	// assuming ethernet MAC
	MACLen = 6
)

type FieldType int

const (
	FieldTypeMAC        FieldType = 0x01
	FieldTypeMACAndIP   FieldType = 0x02
	FieldTypeFirmware   FieldType = 0x03
	FieldTypeRadioName  FieldType = 0x0b
	FieldTypeModelShort FieldType = 0x0c
	FieldTypeESSID      FieldType = 0x0d
	FieldTypeModelFull  FieldType = 0x14
)

func Discover(target string, timeout time.Duration) ([]*DiscoveryResponse, error) {
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer pc.Close()

	addr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		log.Fatalf("Failed to resolve UDP addr: %v", err)
	}
	go func() {
		if _, err := pc.WriteTo([]byte("\x01\x00\x00\x00"), addr); err != nil {
			log.Fatalf("Failed to send broadcast packet: %v", err)
		}
	}()

	buf := make([]byte, 1024)
	responses := make([]*DiscoveryResponse, 0)
	log.Debugf("Receive timeout: %s", timeout)
	if err := pc.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		log.Fatalf("Failed to set read timeout: %v", err)
	}
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				break
			}
			return nil, fmt.Errorf("failed to read from network: %w", err)
		}
		log.Debugf("%s sent %v", addr, buf[:n])
		r, err := FromBytes(buf[:n])
		if err != nil {
			log.Warnf("Failed to parse discovery response: %v", err)
		} else {
			if r != nil {
				responses = append(responses, r)
			}
		}
	}
	return responses, nil
}

func FromBytes(d []byte) (*DiscoveryResponse, error) {
	if len(d) < 4 {
		return nil, fmt.Errorf("short buffer: want at least 4 bytes, got %d", len(d))
	}
	if !bytes.Equal(d[:len(DiscoveryHeader)], DiscoveryHeader) {
		return nil, fmt.Errorf("not a discovery response")
	}
	payloadLen := int(d[3])
	if payloadLen == 0 {
		// this is a discovery request, not a response. Not returning an error,
		// just ignore it at the caller.
		return nil, nil
	}
	if len(d)-len(DiscoveryHeader)-1 != payloadLen {
		return nil, fmt.Errorf("invalid payload length, got %d, want %d", payloadLen, len(d)-len(DiscoveryHeader)-1)
	}

	offset := len(DiscoveryHeader) + 1
	resp := NewDiscoveryResponse()
	for {
		if offset >= len(d) {
			break
		}
		type_ := FieldType(d[offset])
		offset++
		fieldLen := int(binary.BigEndian.Uint16(d[offset : offset+2]))
		offset += 2
		data := d[offset : offset+fieldLen]
		offset += fieldLen
		switch type_ {
		case FieldTypeMAC:
			if len(data) != MACLen {
				return nil, fmt.Errorf("short MAC field: want %d bytes, got %d", MACLen, len(data))
			}
			// if this was already set by the MAC_and_IP field, it will overwrite it
			resp.MAC = data
		case FieldTypeMACAndIP:
			if len(data) < MACLen+net.IPv4len {
				return nil, fmt.Errorf("short MAC_and_IP field: want at least %d, got %d", MACLen+net.IPv4len, len(data))
			}
			// if this was already set by the MAC field, it will overwrite it
			resp.MAC = data[:MACLen]

			var ip net.IP
			switch len(data[MACLen:]) {
			case net.IPv4len:
				ip = net.IPv4(data[6], data[7], data[8], data[9])
			case net.IPv6len:
				ip = net.IP(data[MACLen:])
			default:
				return nil, fmt.Errorf("invalid IPv6 address length: want %d, got %d", net.IPv6len, len(data[MACLen:]))
			}
			resp.IP = ip
		case FieldTypeFirmware:
			resp.Firmware = string(data)
		case FieldTypeRadioName:
			resp.RadioName = string(data)
		case FieldTypeModelShort:
			resp.ModelShort = string(data)
		case FieldTypeModelFull:
			resp.ModelFull = string(data)
		case FieldTypeESSID:
			resp.ESSID = string(data)
		default:
			resp.Unknown[type_] = data
		}
	}
	return resp, nil
}

func NewDiscoveryResponse() *DiscoveryResponse {
	return &DiscoveryResponse{
		Unknown: make(map[FieldType][]byte),
	}
}

type DiscoveryResponse struct {
	MAC        xjson.HardwareAddr
	IP         net.IP
	Firmware   string
	RadioName  string
	ModelShort string
	ESSID      string
	ModelFull  string
	Unknown    map[FieldType][]byte
}

func (d *DiscoveryResponse) String() string {
	return fmt.Sprintf(`ip=%s mac=%s model_short=%s model_full=%s radio_name=%s essid=%s firmware=%s`, d.IP, d.MAC, d.ModelShort, d.ModelFull, d.RadioName, d.ESSID, d.Firmware)
}
