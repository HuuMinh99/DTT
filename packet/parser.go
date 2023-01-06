// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package packet

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sensoroni/sensoroni/model"
)

var SupportedLayerTypes = [...]gopacket.LayerType{
	layers.LayerTypeARP,
	layers.LayerTypeICMPv4,
	layers.LayerTypeICMPv6,
	layers.LayerTypeIPSecAH,
	layers.LayerTypeIPSecESP,
	layers.LayerTypeNTP,
	layers.LayerTypeSIP,
	layers.LayerTypeTLS,
}

func ParsePcap(filename string, offset int, count int) ([]*model.Packet, error) {
	packets := make([]*model.Packet, 0)
	handle, err := pcap.OpenOffline(filename)
	if err == nil {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.DecodeOptions.Lazy = true
		packetSource.DecodeOptions.NoCopy = true
		index := 0
		for pcapPacket := range packetSource.Packets() {
			if pcapPacket != nil {
				index++
				if index >= offset {
					packet := model.NewPacket(index)
					packet.Timestamp = pcapPacket.Metadata().Timestamp
					packet.Length = pcapPacket.Metadata().Length
					parseData(pcapPacket, packet)
					packets = append(packets, packet)
					if len(packets) >= count {
						break
					}
				}
			}
		}
	}
	return packets, err
}

func ParsePcapByTime(filename string, offset int, count int, startTime int64, endTime int64, search string) ([]*model.Packet, int, error) {
	packets := make([]*model.Packet, 0)
	handle, err := pcap.OpenOffline(filename)
	packetsFilter := make([]*model.Packet, 0)
	if err == nil {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.DecodeOptions.Lazy = true
		packetSource.DecodeOptions.NoCopy = true
		index := 0
		for pcapPacket := range packetSource.Packets() {
			if pcapPacket != nil {
				index++
				packet := model.NewPacket(index)
				packet.Timestamp = pcapPacket.Metadata().Timestamp
				packet.Length = pcapPacket.Metadata().Length
				parseData(pcapPacket, packet)
				if startTime != 0 && endTime != 0 {
					if packet.Timestamp.Unix() <= endTime && packet.Timestamp.Unix() >= startTime {
						packetsFilter = append(packetsFilter, packet)
					}
				} else {
					packetsFilter = append(packetsFilter, packet)
				}
			}
		}

		for _, pcap := range packetsFilter {
			if filterSearchPacket(search, pcap) {
				packets = append(packets, pcap)
			}
		}
	}
	result := make([]*model.Packet, 0)
	if offset > len(packets) {
		return result, 0, nil
	}
	end := offset + count
	if end > len(packets) {
		end = len(packets)
	}
	result = packets[offset:end]
	totalPage := math.Ceil(float64(len(packets) / count))
	return result, int(totalPage), err
}

func filterSearchPacket(search string, packet *model.Packet) bool {
	if search == "" {
		return true
	}
	if strings.Contains(packet.SrcIp, search) {
		return true
	}
	if strings.Contains(packet.DstIp, search) {
		return true
	}
	if strings.Contains(strconv.Itoa(packet.DstPort), search) {
		return true
	}
	if strings.Contains(strconv.Itoa(packet.SrcPort), search) {
		return true
	}
	return false
}

func overrideType(packet *model.Packet, layerType gopacket.LayerType) {
	if layerType != gopacket.LayerTypePayload {
		packet.Type = layerType.String()
	}
}

func parseData(pcapPacket gopacket.Packet, packet *model.Packet) {
	layer := pcapPacket.Layer(layers.LayerTypeEthernet)
	if layer != nil {
		layer := layer.(*layers.Ethernet)
		packet.SrcMac = layer.SrcMAC.String()
		packet.DstMac = layer.DstMAC.String()
	}

	layer = pcapPacket.Layer(layers.LayerTypeIPv6)
	if layer != nil {
		layer := layer.(*layers.IPv6)
		// layer1 := pcapPacket.Layer(layers.LayerTypeIPv6).(*layers.IPv6Routing)
		packet.Version = int(layer.Version)
		packet.NextHeader = layer.NextHeader.String()
		packet.HopLimit = int(layer.HopLimit)
		packet.RoutingType = int(pcapPacket.Layer(layers.LayerTypeIPv6).(*layers.IPv6Routing).RoutingType)
		packet.SrcIp = layer.SrcIP.String()
		packet.DstIp = layer.DstIP.String()
	} else {
		layer = pcapPacket.Layer(layers.LayerTypeIPv4)
		if layer != nil {
			layer := layer.(*layers.IPv4)
			packet.Version = int(layer.Version)
			packet.HeaderLength = int(layer.IHL)
			packet.Id = int(layer.Id)
			packet.FragmentOffset = int(layer.FragOffset)
			packet.TimetoLive = int(layer.TTL)
			packet.Protocol = layer.Protocol.String()
			packet.Options = layer.Options
			packet.SrcIp = layer.SrcIP.String()
			packet.DstIp = layer.DstIP.String()
		}
	}

	for _, layerType := range SupportedLayerTypes {
		layer = pcapPacket.Layer(layerType)
		if layer != nil {
			overrideType(packet, layer.LayerType())
		}
	}
	layer = pcapPacket.Layer(layers.LayerTypeICMPv4)
	if layer != nil {
		layer := layer.(*layers.ICMPv4)
		packet.Checksum = int(layer.Checksum)
		packet.ICMPCode = int(layer.TypeCode.Code())
		packet.ICMPType = int(layer.TypeCode.Type())
		overrideType(packet, layer.LayerType())
	}

	layer = pcapPacket.Layer(layers.LayerTypeICMPv6)
	if layer != nil {
		layer := layer.(*layers.ICMPv6)
		packet.Checksum = int(layer.Checksum)
		packet.ICMPCode = int(layer.TypeCode.Code())
		packet.ICMPType = int(layer.TypeCode.Type())
		overrideType(packet, layer.LayerType())
	}

	layer = pcapPacket.Layer(layers.LayerTypeTCP)
	if layer != nil {
		layer := layer.(*layers.TCP)
		packet.SrcPort = int(layer.SrcPort)
		packet.DstPort = int(layer.DstPort)
		packet.Sequence = int(layer.Seq)
		packet.Acknowledge = int(layer.Ack)
		packet.Window = int(layer.Window)
		packet.Checksum = int(layer.Checksum)
		packet.PayloadOffset = int(layer.DataOffset)
		packet.Reserved = 0
		packet.UrgentPointer = int(layer.Urgent)
		packet.Options = layer.Options
		if layer.SYN {
			packet.Flags = append(packet.Flags, "SYN")
		}
		if layer.PSH {
			packet.Flags = append(packet.Flags, "PSH")
		}
		if layer.FIN {
			packet.Flags = append(packet.Flags, "FIN")
		}
		if layer.RST {
			packet.Flags = append(packet.Flags, "RST")
		}
		if layer.ACK {
			packet.Flags = append(packet.Flags, "ACK")
		}
		overrideType(packet, layer.SrcPort.LayerType())
		overrideType(packet, layer.DstPort.LayerType())
		overrideType(packet, layer.LayerType())
	}

	layer = pcapPacket.Layer(layers.LayerTypeUDP)
	if layer != nil {
		layer := layer.(*layers.UDP)
		packet.SrcPort = int(layer.SrcPort)
		packet.DstPort = int(layer.DstPort)
		packet.Checksum = int(layer.Checksum)
		overrideType(packet, layer.NextLayerType())
		overrideType(packet, layer.LayerType())
	}

	packetLayers := pcapPacket.Layers()
	topLayer := packetLayers[len(packetLayers)-1]
	overrideType(packet, topLayer.LayerType())

	packet.Payload = base64.StdEncoding.EncodeToString(pcapPacket.Data())
	packet.PayloadOffset = 0
}
