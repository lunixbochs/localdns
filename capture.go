package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

type dhcpLease struct {
	mac      net.HardwareAddr
	hostname string
	ip       net.IP
}

func newCapture(device string) (*gopacket.PacketSource, error) {
	addrFilter := ""
	filter := fmt.Sprintf("port 68 %s", addrFilter)

	if handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever); err != nil {
		return nil, err
	} else if err := handle.SetBPFFilter(filter); err != nil {
		return nil, err
	} else if err := handle.SetDirection(pcap.DirectionIn); err != nil {
		return nil, err
	} else {
		return gopacket.NewPacketSource(handle, handle.LinkType()), nil
	}
}

func Capture(device string) (<-chan dhcpLease, error) {
	capture, err := newCapture(device)
	if err != nil {
		return nil, err
	}
	ret := make(chan dhcpLease)
	go func() {
		macMap := make(map[string]string)
		for packet := range capture.Packets() {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			// ip, _ := ipLayer.(*layers.IPv4)
			for _, layer := range packet.Layers() {
				switch layer := layer.(type) {
				case *layers.DHCPv4:
					var msgType layers.DHCPMsgType
					var hostname string
					for _, opt := range layer.Options {
						switch opt.Type {
						case layers.DHCPOptMessageType:
							msgType = layers.DHCPMsgType(opt.Data[0])
						case layers.DHCPOptHostname:
							hostname = string(opt.Data)
						}
					}
					switch msgType {
					case layers.DHCPMsgTypeRequest:
						macMap[layer.ClientHWAddr.String()] = hostname
					case layers.DHCPMsgTypeAck:
						hostname = macMap[layer.ClientHWAddr.String()]
						if hostname != "" {
							ret <- dhcpLease{hostname: hostname, ip: layer.YourClientIP, mac: layer.ClientHWAddr}
						}
					}
				}
			}
		}
	}()
	return ret, nil
}
