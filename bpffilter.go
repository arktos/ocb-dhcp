// +build openbsd freebsd darwin

package main

import (
	"fmt"
	"github.com/arktos/raw"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/krolaw/dhcp4"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"net"
	"os"
)

type BPFListener struct {
	// This struct tries to mask that a socket bound to INADDR_ANY can't broadcast
	// on a specific interface.
	Iface  *net.Interface
	sip    net.IP
	handle *raw.Conn
}

// Implement type serveConn interface {}
func (b *BPFListener) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var src_addr net.UDPAddr
	buf := make([]byte, b.Iface.MTU)
	n, addr, err = b.handle.ReadFrom(buf) // buf should now contain an ethernet frame.

	packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)

	iplayer := packet.Layer(layers.LayerTypeIPv4)

	if iplayer != nil {
		ip, _ := iplayer.(*layers.IPv4)
		src_addr.IP = ip.SrcIP
	} else {
		fmt.Println("Couldn't decode packet")
		return 0, &src_addr, err
	}

	udplayer := packet.Layer(layers.LayerTypeUDP)
	if udplayer != nil {
		udpp, _ := udplayer.(*layers.UDP)
		src_addr.Port = int(udpp.SrcPort)
		copy(p, udpp.Payload)
	} else {
		fmt.Println("Couldn't decode packet")
		return 0, &src_addr, err
	}
	return len(p), &src_addr, nil
}

func (b *BPFListener) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ipStr, _, err := net.SplitHostPort(addr.String())
	dst_ip := net.ParseIP(ipStr)
	var dst_hwaddr net.HardwareAddr
	var iplayer *layers.IPv4

	iplayer = &layers.IPv4{
		Version:    4,   // uint8
		IHL:        5,   // uint8
		TOS:        0,   // uint8
		Id:         0,   // uint16
		Flags:      0,   // IPv4Flag
		FragOffset: 0,   // uint16
		TTL:        255, // uint8
		Protocol:   17,  // IPProtocol UDP(17)
	}

	// The reply can be sent in two different ways:
	// 1. As an IP broadcast.
	// 2. As an IP unicast.
	// The first is easy, the broadcast adresses are all bits set to
	// one in both the IP packet and the ethernet frame. Also, the sending
	// IP is simple, all zeroes.
	// The second case is trickier. First we need to find out the recipient's
	// IP. Since we have the clients hardware adress in the chaddr field of
	// the DHCP packet, this is easily done. As for the sending IP, I don't
	// know.
	// Anyhow, both types of replies consists of an IP packet.

	if dst_ip.Equal(net.IPv4bcast) {
		iplayer.SrcIP = net.IPv4zero
		iplayer.DstIP = net.IPv4bcast
		dst_hwaddr = layers.EthernetBroadcast
	} else {
		pp := dhcp4.Packet(p)
		dst_addr, _, _ := net.SplitHostPort(addr.String())
		iplayer.SrcIP = b.sip
		iplayer.DstIP = net.ParseIP(dst_addr)
		dst_hwaddr = pp.CHAddr() // Is this a bad hack?
	}

	udplayer := &layers.UDP{SrcPort: 67, DstPort: 68}
	udplayer.SetNetworkLayerForChecksum(iplayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: b.Iface.HardwareAddr, DstMAC: dst_hwaddr, EthernetType: 0x800},
		iplayer,
		udplayer,
		gopacket.Payload(p))

	// Send it.
	return b.handle.WriteTo(buf.Bytes(), &raw.Addr{})
}

func (b *BPFListener) Close() error {
	b.handle.Close()
	return nil
}

func NewBPFListener(interfaceName string) (*BPFListener, error) {
	var filter []bpf.RawInstruction

	ifi, err := net.InterfaceByName(interfaceName) // Interface index
	if err != nil {
		fmt.Fprintf(os.Stderr, "No interface %s on this host", interfaceName)
		os.Exit(1)
	}

	// Not the most elegant way of doing things :(
	addrs, _ := ifi.Addrs() //[]Addr
	sip := net.ParseIP(addrs[0].String())

	// Open the device raw device for IP over ethernet
	config := &raw.Config{} // Ignored but needed on BSD
	h, err := raw.ListenPacket(ifi, 0x0800, config)
	if err != nil {
		defer h.Close()
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	// This BPF program is ported from the one in the OpenBSD DHCPd as are
	// most of the comments. The first load and jump is not strictly necessary
	// when used in conjunction with github.com/mdlayher/raw, raw.ListenPacket
	// filter the frames by itself.
	filter, err = bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 8},
		// Make sure it's a UDP packet...
		// Load the byte at absolute offset 23 into the accumulator.
		// If accumulator equals IPPROTO_UDP do not jump, otherwise jump six steps.
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_UDP, SkipFalse: 6},
		// Make sure this isn't a fragment...
		// The pattern here is obvious, load the half-word at offset 20.
		bpf.LoadAbsolute{Off: 20, Size: 2},
		// What does this do?
		// From https://www.tcpdump.org/papers/bpf-usenix93.pdf
		// (jset performs a “bitwise and” — useful for conditional bit tests)
		// If 0x1fff and whatever is in the halfword at offset 20 results in
		// zero, jump 4 steps, otherwise continue with the next instruction.
		bpf.JumpIf{Cond: bpf.JumpBitsNotSet, Val: 0x1fff, SkipFalse: 4},
		// Get the IP header length...
		bpf.LoadMemShift{Off: 14},
		// Make sure it's to the right port...
		// Load the half-word at the offset given by the BPF index register and then something
		bpf.LoadIndirect{Off: 16, Size: 2},
		// Jump to the end of the program if the value isn't 67.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x43, SkipFalse: 1},
		// Send the packet to userspace
		bpf.RetConstant{Val: 2048},
		// Verdict is "ignore packet."
		bpf.RetConstant{Val: 0},
	})

	if err != nil {
		defer h.Close()
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	h.SetBPF(filter)

	return &BPFListener{Iface: ifi, handle: h, sip: sip}, nil

}
