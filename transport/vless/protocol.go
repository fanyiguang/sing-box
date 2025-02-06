package vless

import (
	"bytes"
	"encoding/binary"
	"google.golang.org/protobuf/proto"
	"io"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/rw"
)

const (
	Version    = 0
	FlowVision = "xtls-rprx-vision"
)

type Request struct {
	UUID        [16]byte
	Command     byte
	Destination M.Socksaddr
	Flow        string
	Token       string
	TraceId     string
}

func (r *Request) AddonsLen() (int, error) {
	marshal, err := proto.Marshal(&ClientAddons{
		Flow:    r.Flow,
		TraceId: r.TraceId,
		Token:   r.Token,
	})
	if err != nil {
		return 0, err
	}

	return len(marshal), nil
}

func (r *Request) Addons() ([]byte, error) {
	return proto.Marshal(&ClientAddons{
		Flow:    r.Flow,
		TraceId: r.TraceId,
		Token:   r.Token,
	})
}

func ReadRequest(reader io.Reader) (*Request, error) {
	var request Request

	var version uint8
	err := binary.Read(reader, binary.BigEndian, &version)
	if err != nil {
		return nil, err
	}
	if version != Version {
		return nil, E.New("unknown version: ", version)
	}

	_, err = io.ReadFull(reader, request.UUID[:])
	if err != nil {
		return nil, err
	}

	var addonsLen uint8
	err = binary.Read(reader, binary.BigEndian, &addonsLen)
	if err != nil {
		return nil, err
	}

	if addonsLen > 0 {
		addonsBytes, err := rw.ReadBytes(reader, int(addonsLen))
		if err != nil {
			return nil, err
		}

		addons, err := readAddons(bytes.NewReader(addonsBytes))
		if err != nil {
			return nil, err
		}
		request.Flow = addons.Flow
	}

	err = binary.Read(reader, binary.BigEndian, &request.Command)
	if err != nil {
		return nil, err
	}

	if request.Command != vmess.CommandMux {
		request.Destination, err = vmess.AddressSerializer.ReadAddrPort(reader)
		if err != nil {
			return nil, err
		}
	}

	return &request, nil
}

type Addons struct {
	Flow string
	Seed string
}

func readAddons(reader io.Reader) (*Addons, error) {
	protoHeader, err := rw.ReadByte(reader)
	if err != nil {
		return nil, err
	}
	if protoHeader != 10 {
		return nil, E.New("unknown protobuf message header: ", protoHeader)
	}

	var addons Addons

	flowLen, err := rw.ReadUVariant(reader)
	if err != nil {
		if err == io.EOF {
			return &addons, nil
		}
		return nil, err
	}
	flowBytes, err := rw.ReadBytes(reader, int(flowLen))
	if err != nil {
		return nil, err
	}
	addons.Flow = string(flowBytes)

	seedLen, err := rw.ReadUVariant(reader)
	if err != nil {
		if err == io.EOF {
			return &addons, nil
		}
		return nil, err
	}
	seedBytes, err := rw.ReadBytes(reader, int(seedLen))
	if err != nil {
		return nil, err
	}
	addons.Seed = string(seedBytes)

	return &addons, nil
}

func WriteRequest(writer io.Writer, request Request, payload []byte) error {
	var requestLen int
	requestLen += 1  // version
	requestLen += 16 // uuid
	requestLen += 1  // protobuf length

	var err error
	var addonsLen int
	if request.Flow != "" {
		//addonsLen += 1 // protobuf header
		//addonsLen += rw.UVariantLen(uint64(len(request.Flow)))
		//addonsLen += len(request.Flow)
		//requestLen += addonsLen
		addonsLen, err = request.AddonsLen()
		if err != nil {
			return err
		}
		requestLen += addonsLen
	}
	requestLen += 1 // command
	if request.Command != vmess.CommandMux {
		requestLen += vmess.AddressSerializer.AddrPortLen(request.Destination)
	}
	requestLen += len(payload)
	buffer := buf.NewSize(requestLen)
	defer buffer.Release()
	common.Must(
		buffer.WriteByte(Version),
		common.Error(buffer.Write(request.UUID[:])),
		buffer.WriteByte(byte(addonsLen)),
	)
	if addonsLen > 0 {
		//common.Must(buffer.WriteByte(10))
		//binary.PutUvarint(buffer.Extend(rw.UVariantLen(uint64(len(request.Flow)))), uint64(len(request.Flow)))
		//common.Must(common.Error(buffer.WriteString(request.Flow)))
		addons, err := request.Addons()
		if err != nil {
			return err
		}
		common.Must(common.Error(buffer.Write(addons)))
	}
	common.Must(
		buffer.WriteByte(request.Command),
	)

	if request.Command != vmess.CommandMux {
		err := vmess.AddressSerializer.WriteAddrPort(buffer, request.Destination)
		if err != nil {
			return err
		}
	}

	common.Must1(buffer.Write(payload))
	return common.Error(writer.Write(buffer.Bytes()))
}

func EncodeRequest(request Request, buffer *buf.Buffer) error {
	var requestLen int
	requestLen += 1  // version
	requestLen += 16 // uuid
	requestLen += 1  // protobuf length

	var err error
	var addonsLen int
	if request.Flow != "" {
		//addonsLen += 1 // protobuf header
		//addonsLen += rw.UVariantLen(uint64(len(request.Flow)))
		//addonsLen += len(request.Flow)
		//requestLen += addonsLen

		addonsLen, err = request.AddonsLen()
		if err != nil {
			return err
		}
		requestLen += addonsLen
	}
	requestLen += 1 // command
	if request.Command != vmess.CommandMux {
		requestLen += vmess.AddressSerializer.AddrPortLen(request.Destination)
	}
	common.Must(
		buffer.WriteByte(Version),
		common.Error(buffer.Write(request.UUID[:])),
		buffer.WriteByte(byte(addonsLen)),
	)
	if addonsLen > 0 {
		//common.Must(buffer.WriteByte(10))
		//binary.PutUvarint(buffer.Extend(rw.UVariantLen(uint64(len(request.Flow)))), uint64(len(request.Flow)))
		//common.Must(common.Error(buffer.WriteString(request.Flow)))

		addons, err := request.Addons()
		if err != nil {
			return err
		}
		common.Must(common.Error(buffer.Write(addons)))
	}
	common.Must(
		buffer.WriteByte(request.Command),
	)

	if request.Command != vmess.CommandMux {
		err := vmess.AddressSerializer.WriteAddrPort(buffer, request.Destination)
		if err != nil {
			return err
		}
	}
	return nil
}

func RequestLen(request Request) int {
	var requestLen int
	requestLen += 1  // version
	requestLen += 16 // uuid
	requestLen += 1  // protobuf length

	var addonsLen int
	if request.Flow != "" {
		//addonsLen += 1 // protobuf header
		//addonsLen += rw.UVariantLen(uint64(len(request.Flow)))
		//addonsLen += len(request.Flow)
		//requestLen += addonsLen

		addonsLen, _ = request.AddonsLen()
		requestLen += addonsLen
	}
	requestLen += 1 // command
	if request.Command != vmess.CommandMux {
		requestLen += vmess.AddressSerializer.AddrPortLen(request.Destination)
	}
	return requestLen
}

func WritePacketRequest(writer io.Writer, request Request, payload []byte) error {
	var requestLen int
	requestLen += 1  // version
	requestLen += 16 // uuid
	requestLen += 1  // protobuf length
	var addonsLen int
	/*if request.Flow != "" {
		addonsLen += 1 // protobuf header
		addonsLen += rw.UVariantLen(uint64(len(request.Flow)))
		addonsLen += len(request.Flow)
		requestLen += addonsLen
	}*/
	requestLen += 1 // command
	requestLen += vmess.AddressSerializer.AddrPortLen(request.Destination)
	if len(payload) > 0 {
		requestLen += 2
		requestLen += len(payload)
	}
	buffer := buf.NewSize(requestLen)
	defer buffer.Release()
	common.Must(
		buffer.WriteByte(Version),
		common.Error(buffer.Write(request.UUID[:])),
		buffer.WriteByte(byte(addonsLen)),
	)

	if addonsLen > 0 {
		//common.Must(buffer.WriteByte(10))
		//binary.PutUvarint(buffer.Extend(rw.UVariantLen(uint64(len(request.Flow)))), uint64(len(request.Flow)))
		//common.Must(common.Error(buffer.WriteString(request.Flow)))

		addons, err := request.Addons()
		if err != nil {
			return err
		}
		common.Must(common.Error(buffer.Write(addons)))
	}

	common.Must(buffer.WriteByte(vmess.CommandUDP))

	err := vmess.AddressSerializer.WriteAddrPort(buffer, request.Destination)
	if err != nil {
		return err
	}

	if len(payload) > 0 {
		common.Must(
			binary.Write(buffer, binary.BigEndian, uint16(len(payload))),
			common.Error(buffer.Write(payload)),
		)
	}

	return common.Error(writer.Write(buffer.Bytes()))
}

func ReadResponse(reader io.Reader) error {
	version, err := rw.ReadByte(reader)
	if err != nil {
		return err
	}
	if version != Version {
		return E.New("unknown version: ", version)
	}
	protobufLength, err := rw.ReadByte(reader)
	if err != nil {
		return err
	}
	if protobufLength > 0 {
		err = rw.SkipN(reader, int(protobufLength))
		if err != nil {
			return err
		}
	}
	return nil
}
