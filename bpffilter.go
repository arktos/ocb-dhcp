// +build openbsd freebsd

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
	Iface  *net.Interface
	sip    net.IP
	handle *raw.Conn
}

// Implement type ServeConn interface {}
func (b *BPFListener) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, 1600)
	var srcaddr net.UDPAddr

	_, _, e := b.handle.ReadFrom(buf)

	if e != nil {
		fmt.Fprintln(os.Stdout, e)
		return 0, nil, e
	}

	packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		i, _ := ipLayer.(*layers.IPv4)
		srcaddr.IP = i.SrcIP
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcaddr.Port = int(udp.SrcPort)
		p = udp.LayerPayload()
		// fmt.Println(p)
	}
	return len(p), &srcaddr, nil
}

func (b *BPFListener) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ipStr, _, err := net.SplitHostPort(addr.String())
	dst_ip := net.ParseIP(ipStr)
	var dst_hwaddr net.HardwareAddr

	// The reply can be sent in two different ways:
	// 1. As an IP broadcast.
	// 2. As an IP unicast.
	// The first is easy, the broadcast adresses are all bits set to
	// one in both the IP packet and the ethernet frame. Also, the sending
	// IP is simple, all zeroes.
	// The second case is trickier. First we need to find out the recipient's
	// IP. Since we have the client's hardware adress in the chaddr field of
	// the DHCP packet, this is easily done. As for the sending IP, I don't
	// know.
	// Anyhow, both types of replies consists of an IP packet.
	iph := &layers.IPv4{}
	udph := &layers.UDP{SrcPort: 67, DstPort: 68}
	frame := &layers.Ethernet{EthernetType: 0x800, SrcMAC: b.Iface.HardwareAddr}

	udph.SetNetworkLayerForChecksum(iph)

	if dst_ip.Equal(net.IPv4bcast) {
		iph.SrcIP = net.IPv4zero
		iph.DstIP = net.IPv4bcast
		frame.DstMAC = layers.EthernetBroadcast

	} else {
		// FIXME
		pp := dhcp4.Packet(p)
		dst_addr, _, _ := net.SplitHostPort(addr.String())

		iph.SrcIP = b.sip
		iph.DstIP = net.ParseIP(dst_addr)
		frame.DstMAC = pp.CHAddr() // Is this a bad hack?
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	gopacket.SerializeLayers(buf, opts, frame, iph, udph, gopacket.Payload(p))

	// Send it.
	dst_addr := &raw.Addr{HardwareAddr: dst_hwaddr}
	return b.handle.WriteTo(buf.Bytes(), dst_addr)
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

	// Open the raw device for IP over ethernet
	config := &raw.Config{} // Needed but ignored on BSD
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

	// We now have a filtering BPF listener, return it.

	return &BPFListener{Iface: ifi, handle: h, sip: sip}, nil

}
