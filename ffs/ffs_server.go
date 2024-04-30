package ffs

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"sync"
	"syscall"

	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/util"
)

var ffsLogger = util.NewLogger("[FFS] ", util.LogLevelTrace)

const (
	FUNCTIONFS_DESCRIPTORS_MAGIC    = 1
	FUNCTIONFS_STRINGS_MAGIC        = 2
	FUNCTIONFS_DESCRIPTORS_MAGIC_V2 = 3
)

const (
	FUNCTIONFS_HAS_FS_DESC    = 1
	FUNCTIONFS_HAS_HS_DESC    = 2
	FUNCTIONFS_HAS_SS_DESC    = 4
	FUNCTIONFS_HAS_MS_OS_DESC = 8
	FUNCTIONFS_VIRTUAL_ADDR   = 16
	FUNCTIONFS_EVENTFD        = 32
	FUNCTIONFS_ALL_CTRL_RECIP = 64
	FUNCTIONFS_CONFIG0_SETUP  = 128
)

type USBFunctionFSDescsHeadV2 struct {
	magic  uint32
	length uint32
	flags  uint32
}

type USBFunctionFSStringsHead struct {
	magic     uint32
	length    uint32
	strCount  uint32
	langCount uint32
}

type Endpoint struct {
	fd int
	fn string
}

func NewEndpoint(name string) *Endpoint {
	fd, err := syscall.Open(name, syscall.O_RDWR, 0)
	util.CheckErr(err, "Could not open "+name)
	ep := new(Endpoint)
	ep.fn = name
	ep.fd = fd
	return ep
}

func (ep *Endpoint) needRetry(err error) bool {
	if errno, ok := err.(syscall.Errno); ok {
		if errno == syscall.EINTR || errno == syscall.EAGAIN {
			return true
		}
	}
	return false
}

func (ep *Endpoint) Read(b []byte) int {
	for {
		n, err := syscall.Read(ep.fd, b)
		if ep.needRetry(err) {
			continue
		}
		util.CheckErr(err, "Could not read "+ep.fn)
		ffsLogger.Printf("[%s] read %d/%d: %s\n", ep.fn, n, len(b), hex.EncodeToString(b[:n]))
		return n
	}
}

func (ep *Endpoint) Write(b []byte) {
	for {
		n, err := syscall.Write(ep.fd, b)
		if ep.needRetry(err) {
			continue
		}
		util.CheckErr(err, "Could not write "+ep.fn)
		ffsLogger.Printf("[%s] write %d/%d: %s\n", ep.fn, n, len(b), hex.EncodeToString(b[:n]))
		return
	}
}

func (ep *Endpoint) Close() {
	err := syscall.Close(ep.fd)
	util.CheckErr(err, "Could not close "+ep.fn)
}

// FFS types

type USBFunctionFSEvent struct {
	Setup usbSetupPacket
	Type  uint8
	Pad   [3]uint8
}

const (
	FUNCTIONFS_BIND   uint8 = 0
	FUNCTIONFS_UNBIND       = 1

	FUNCTIONFS_ENABLE  = 2
	FUNCTIONFS_DISABLE = 3

	FUNCTIONFS_SETUP = 4

	FUNCTIONFS_SUSPEND = 5
	FUNCTIONFS_RESUME  = 6
)

type FFSServer struct {
	ctapHid       *ctap_hid.CTAPHIDServer
	responseMutex *sync.Mutex
	response      []byte
}

func NewFFSServer(ctapHid *ctap_hid.CTAPHIDServer) *FFSServer {
	server := new(FFSServer)
	server.ctapHid = ctapHid
	server.responseMutex = &sync.Mutex{}
	return server
}

func (server *FFSServer) Start() {
	ffsLogger.Println("Starting FFS server...")
	ep0 := NewEndpoint("ep0")
	server.initEp0(ep0)

	// by now ep1 and ep2 should appear
	ep1 := NewEndpoint("ep1")
	ep2 := NewEndpoint("ep2")

	responseHandler := func(response []byte) {
		server.responseMutex.Lock()
		server.response = append(server.response, response...)
		server.responseMutex.Unlock()
	}
	server.ctapHid.SetResponseHandler(responseHandler)

	server.handleEps(ep0, ep1, ep2)

	for _, ep := range []*Endpoint{ep0, ep1, ep2} {
		ep.Close()
	}
	ep0.Close()

}

func (server *FFSServer) getHIDReport() []byte {
	// Manually calculated using the HID Report calculator for a FIDO device
	return []byte{6, 208, 241, 9, 1, 161, 1, 9, 32, 20, 37, 255, 117, 8, 149, 64, 129, 2, 9, 33, 20, 37, 255, 117, 8, 149, 64, 145, 2, 192}
}

func (server *FFSServer) getFFSDescHeader() USBFunctionFSDescsHeadV2 {
	totalLength := uint32(util.SizeOf[USBFunctionFSDescsHeadV2]()) + uint32(4) +
		uint32(util.SizeOf[usbInterfaceDescriptor]()) +
		uint32(util.SizeOf[usbHIDDescriptor]()) +
		uint32(util.SizeOf[usbEndpointDescriptor]()*2)
	return USBFunctionFSDescsHeadV2{
		magic:  FUNCTIONFS_DESCRIPTORS_MAGIC_V2,
		flags:  FUNCTIONFS_HAS_HS_DESC,
		length: totalLength,
	}
}

func (server *FFSServer) getEndpointDescriptors() []usbEndpointDescriptor {
	length := util.SizeOf[usbEndpointDescriptor]()
	return []usbEndpointDescriptor{
		{
			BLength:          length,
			BDescriptorType:  usbDescriptorEndpoint,
			BEndpointAddress: 0b10000001,
			BmAttributes:     0b00000011,
			WMaxPacketSize:   64,
			BInterval:        1,
		},
		{
			BLength:          length,
			BDescriptorType:  usbDescriptorEndpoint,
			BEndpointAddress: 0b00000010,
			BmAttributes:     0b00000011,
			WMaxPacketSize:   64,
			BInterval:        1,
		},
	}
}

func (server *FFSServer) getInterfaceDescriptor() usbInterfaceDescriptor {
	return usbInterfaceDescriptor{
		BLength:            util.SizeOf[usbInterfaceDescriptor](),
		BDescriptorType:    usbDescriptorInterface,
		BInterfaceNumber:   0,
		BAlternateSetting:  0,
		BNumEndpoints:      2,
		BInterfaceClass:    usbInterfaceClassHID,
		BInterfaceSubclass: 0,
		BInterfaceProtocol: 0,
		IInterface:         5,
	}
}

func (server *FFSServer) getHIDDescriptor(hidReportDescriptor []byte) usbHIDDescriptor {
	return usbHIDDescriptor{
		BLength:                 util.SizeOf[usbHIDDescriptor](),
		BDescriptorType:         usbDescriptorHID,
		BcdHID:                  0x0101,
		BCountryCode:            0,
		BNumDescriptors:         1,
		BClassDescriptorType:    usbDescriptorHIDReport,
		WReportDescriptorLength: uint16(len(hidReportDescriptor)),
	}
}

func (server *FFSServer) deviceDescriptors() []byte {
	hidReport := server.getHIDReport()
	buffer := new(bytes.Buffer)
	header := server.getFFSDescHeader()
	interfaceDescriptor := server.getInterfaceDescriptor()
	hid := server.getHIDDescriptor(hidReport)
	buffer.Write(util.ToLE(header))
	buffer.Write(util.ToLE(uint32(4)))
	buffer.Write(util.ToLE(interfaceDescriptor))
	buffer.Write(util.ToLE(hid))
	endpoints := server.getEndpointDescriptors()
	for _, endpoint := range endpoints {
		buffer.Write(util.ToLE(endpoint))
	}
	return buffer.Bytes()
}

func (server *FFSServer) getStrings() []string {
	strings := []string{
		"No Company",
		"Virtual FIDO",
		"No Serial Number",
		"String 4",
		"Default Interface",
	}
	return strings
}

func (server *FFSServer) getFFSStringsHeader() USBFunctionFSStringsHead {
	totalLength := int(util.SizeOf[USBFunctionFSStringsHead]()) + 2
	for _, s := range server.getStrings() {
		totalLength += len([]byte(s)) + 1
	}
	return USBFunctionFSStringsHead{
		magic:     FUNCTIONFS_STRINGS_MAGIC,
		length:    uint32(totalLength),
		strCount:  5,
		langCount: 1,
	}
}

func (server *FFSServer) deviceStrings() []byte {
	buffer := new(bytes.Buffer)
	header := server.getFFSStringsHeader()
	buffer.Write(util.ToLE(header))
	buffer.Write(util.ToLE(uint16(usbLangIDEngUSA)))
	for _, s := range server.getStrings() {
		buffer.Write(append([]byte(s), 0))
	}
	return buffer.Bytes()
}

func (server *FFSServer) initEp0(ep *Endpoint) {
	ep.Write(server.deviceDescriptors())
	ep.Write(server.deviceStrings())
}

func (server *FFSServer) handleEps(ep0 *Endpoint, ep1 *Endpoint, ep2 *Endpoint) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func(idx uint32, ep *Endpoint) {
		server.handleEp0(idx, ep)
		defer wg.Done()
	}(uint32(0), ep0)
	wg.Add(1)
	go func(idx uint32, ep *Endpoint) {
		server.handleEpOut(idx, ep)
		defer wg.Done()
	}(uint32(2), ep2)
	wg.Add(1)
	go func(idx uint32, ep *Endpoint) {
		server.handleEpIn(idx, ep)
		defer wg.Done()
	}(uint32(1), ep1)
	wg.Wait()
}

func (server *FFSServer) handleEpOut(idx uint32, ep *Endpoint) {
	ffsLogger.Println("start handling ep out")
	buf := make([]byte, 64)
	for {
		n := ep.Read(buf)
		if n > 0 {
			server.ctapHid.HandleMessage(buf[:n])
		}
	}
}

func (server *FFSServer) handleEpIn(idx uint32, ep *Endpoint) {
	ffsLogger.Println("start handling ep in")
	var id uint32 = 0
	for {
		server.responseMutex.Lock()
		if server.response != nil && len(server.response) > 0 {
			ep.Write(server.response)
		}
		server.response = nil
		id = id + 1
		server.responseMutex.Unlock()
	}
}

func (server *FFSServer) handleEp0(idx uint32, ep *Endpoint) {
	ffsLogger.Println("start handling ep0")
	for {
		buf := make([]byte, 4096)
		n := ep.Read(buf)
		if n > 0 {
			ev := util.ReadLE[USBFunctionFSEvent](bytes.NewBuffer(buf[:n]))
			switch t := ev.Type; t {
			case FUNCTIONFS_BIND:
			case FUNCTIONFS_UNBIND:
			case FUNCTIONFS_ENABLE:
			case FUNCTIONFS_DISABLE:
			case FUNCTIONFS_SUSPEND:
			case FUNCTIONFS_RESUME:
			case FUNCTIONFS_SETUP:
				if ev.Setup.BmRequestType&0x80 == 0x80 && ev.Setup.BRequest == usbRequestGetDescriptor {
					ffsLogger.Println("setup packet: ", ev.Setup)
					submitResponse := func(n int) {
						if n > 0 {
							ep.Write(buf[:n])
						}
					}
					r := server.getHIDReport()
					copy(buf, r)
					submitResponse(len(r))
				}
			default:
				panic(fmt.Sprint("Unknown event type %d", ev.Type))
			}
		}
	}

}
