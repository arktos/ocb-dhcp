// +build openbsd freebsd

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/krolaw/dhcp4"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
	//	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"net"
	"os"
)

//bpf.Assemble([]bpf.Instruction{	// Load "EtherType" field from the ethernet header.
// 	bpf.LoadAbsolute{Off: 12, Size: 2},
// Skip over the next instruction if EtherType is not IP.
//	bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x0800, SkipTrue: 1},
// Jump again if it's not an UDP packet.
//    bpf.LoadAbsolute{Off: 23, Size: 4}
//	bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.IPPROTO_UDP, SkipTrue: 1},

// Verdict is "send up to 4k of the packet to userspace."
// 	bpf.RetConstant{Val: 4096},
// Verdict is "ignore packet."
// 	bpf.RetConstant{Val: 0},
//})

// /* Make sure this is an IP packet... */
// BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12), // Load BPF half-word (BPF_H, 2 bytes) at absolute offset 12 into the accumulator
// Jump zero steps if accumulator value is ETHERTYPE_IP, otherwise jump eight steps
// BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 8
//
// /* Make sure it's a UDP packet... */
// BPF_LD + BPF_B + BPF_ABS, 23 // Load the byte at absolute offset 23 into the accumulator.
// If accumulator equals IPPROTO_UDP do not jump, otherwise jump six steps.
// BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 6
//
// /* Make sure this isn't a fragment... */
// BPF_LD + BPF_H + BPF_ABS, 20 // The pattern here is obvious, load the half-word at offset 20.
// What does this do?
// BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0,
//
// /* Get the IP header length... */
// BPF_LDX + BPF_B + BPF_MSH, 14,
//
// /* Make sure it's to the right port... */
// Load the half-word at the offset given by the BPF index register and then something
// BPF_LD + BPF_H + BPF_IND, 16
// Jump to the end of the program if the value isn't 67.
// BPF_JMP + BPF_JEQ + BPF_K, SERVER_PORT, 0, 1
//
// /* If we passed all the tests, ask for the whole packet. */
// Return a constant value of bytes, (u_int)-1
// BPF_RET+BPF_K, (u_int)-1
//
// /* Otherwise, drop it. */
// BPF_RET+BPF_K, 0

type IPHeader struct {
	vhl   uint8
	tos   uint8
	iplen uint16
	id    uint16
	off   uint16
	ttl   uint8
	proto uint8
	csum  uint16
	src   [4]byte
	dst   [4]byte
}

func (h *IPHeader) checksum() {
	h.csum = 0
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, h)
	h.csum = checksum(b.Bytes())
}

type UDPHeader struct {
	src  uint16
	dst  uint16
	ulen uint16
	csum uint16
}

func (u *UDPHeader) checksum(ip *IPHeader, payload []byte) {
	u.csum = 0
	phdr := pseudohdr{
		ipsrc:   ip.src,
		ipdst:   ip.dst,
		zero:    0,
		ipproto: ip.proto,
		plen:    u.ulen,
	}
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, &phdr)
	binary.Write(&b, binary.BigEndian, u)
	binary.Write(&b, binary.BigEndian, &payload)
	u.csum = checksum(b.Bytes())
}

// pseudo header used for checksum calculation
type pseudohdr struct {
	ipsrc   [4]byte
	ipdst   [4]byte
	zero    uint8
	ipproto uint8
	plen    uint16
}

type UDPDatagram struct {
	srcPort      uint16
	dstPort      uint16
	packetLength uint16
	csum         uint16
	data         *[]byte
}

func NewUDPDatagram(src, dst int, data []byte) (UDPDatagram, error) {
	u := UDPDatagram{}
	l := len(data)
	if l > 65507 {
		e := errors.New("The data is too large to fit into a single UDPDatagram.")
		return u, e
	}

	u.srcPort = uint16(src)
	u.dstPort = uint16(dst)
	u.packetLength = uint16(l + 8)
	u.data = &data
	return u, nil
}

func checksum(buf []byte) uint16 {
	sum := uint32(0)

	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	/*
	 * From RFC 768:
	 * If the computed checksum is zero, it is transmitted as all ones (the
	 * equivalent in one's complement arithmetic). An all zero transmitted
	 * checksum value means that the transmitter generated no checksum (for
	 * debugging or for higher level protocols that don't care).
	 */
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

type BPFListener struct {
	// This struct tries to mask that a socket bound to INADDR_ANY can't broadcast
	// on a specific interface.
	Iface  *net.Interface
	sip    net.IP
	conn   *ipv4.PacketConn
	cm     *ipv4.ControlMessage
	handle *raw.Conn
}

// func (b *BPFListener) ReadRaw(p []byte) (n int, addr net.Addr, err error) {
func (b *BPFListener) ReadRaw(p []byte) (frame ethernet.Frame, err error) {

	var f ethernet.Frame
	data := make([]byte, b.Iface.MTU)
	size, _, _ := b.handle.ReadFrom(data)
	if err != nil {
		fmt.Println(err)
		return f, err
	}
	err = f.UnmarshalBinary(data[:size])
	if err != nil {
		return f, err
	}
	return f, nil
}

// Implement type serveConn interface {}
func (b *BPFListener) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for { // Filter all other interfaces
		n, b.cm, addr, err = b.conn.ReadFrom(p)
		if err != nil || b.cm == nil || b.cm.IfIndex == b.Iface.Index {
			break
		} else {
			fmt.Fprintf(os.Stdout, "Hrmm…")
		}
	}
	return
}

func (b *BPFListener) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ipStr, _, err := net.SplitHostPort(addr.String())
	dst_ip := net.ParseIP(ipStr)
	var dgram bytes.Buffer
	var dst_hwaddr net.HardwareAddr

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
	iph := IPHeader{
		vhl:   0x45,
		tos:   0,
		id:    0x1234, // the kernel overwrites id if it is zero
		off:   0,
		ttl:   64,
		proto: unix.IPPROTO_UDP,
	}

	if dst_ip.Equal(net.IPv4bcast) {
		copy(iph.src[:], net.IPv4zero.To4())
		copy(iph.dst[:], net.IPv4bcast.To4())

		dst_hwaddr = ethernet.Broadcast
	} else {
		pp := dhcp4.Packet(p)
		dst_addr, _, _ := net.SplitHostPort(addr.String())
		dst_ip := net.ParseIP(dst_addr)
		copy(iph.src[:], b.sip.To4())
		copy(iph.dst[:], dst_ip.To4())

		dst_hwaddr = pp.CHAddr() // Is this a bad hack?
	}

	// datagram, err := NewUDPDatagram(67, 68, p)
	// if err != nil {
	//     fmt.Fprintf(os.Stderr, err)
	//     return 0, err
	// }

	udph := UDPHeader{
		src:  uint16(67),
		dst:  uint16(68),
		ulen: uint16(8 + len(p)),
	}
	// The checksum needs some field from the IP header,
	// so wait to calculate the checksum.

	totalLen := 20 + udph.ulen
	if totalLen > 0xffff {
		fmt.Fprintf(os.Stderr, "Message is too large to fit into a single datagram: %v > %v\n", totalLen, 0xffff)
		return 0, err
	}

	iph.iplen = uint16(totalLen)
	iph.checksum()

	// the kernel doesn't touch the UDP checksum, so we can either set it
	// correctly or leave it zero to indicate that we didn't use a checksum
	udph.checksum(&iph, p)

	err = binary.Write(&dgram, binary.BigEndian, &iph)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding the IP header: %v\n", err)
		return 0, err
	}

	err = binary.Write(&dgram, binary.BigEndian, &udph)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding the UDP header: %v\n", err)
		return 0, err
	}

	err = binary.Write(&dgram, binary.BigEndian, &p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding the payload: %v\n", err)
		return 0, err
	}

	buf := dgram.Bytes()

	// Construct the ethernet frame
	frame := &ethernet.Frame{
		Destination: dst_hwaddr,
		Source:      b.Iface.HardwareAddr,
		EtherType:   0x0800,
		Payload:     buf,
	}

	g, err := frame.MarshalBinary()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 0, err
	}

	// Send it.
	dst_addr := &raw.Addr{HardwareAddr: dst_hwaddr}
	return b.handle.WriteTo(g, dst_addr)
}

func (b *BPFListener) Close() error {
	b.handle.Close()
	return nil
}

func NewBPFListener(interfaceName string) (*BPFListener, error) {

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

	// Then set up a normal packet listener.
	l, err := net.ListenPacket("udp4", ":67")
	if err != nil {
		defer l.Close()
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	p := ipv4.NewPacketConn(l)
	if err := p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return nil, err
	}

	return &BPFListener{Iface: ifi, handle: h, conn: p, sip: sip}, nil

}
