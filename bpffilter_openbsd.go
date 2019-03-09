package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"net"
	"os"
)

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
	Iface   *net.Interface
	iface   *net.Interface
	conn    *ipv4.PacketConn
	cm      *ipv4.ControlMessage
	handle  *raw.Conn
	arpconn *arp.Client
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
	var iph IPHeader

	// The reply can be sent in two different ways:
	// 1. As an IP broadcast.
	// 2. As an IP unicast.
	// The first is easy, the broadcast adresses are all bits set to
	// one in both the IP packet and the ethernet frame. Also, the sending
	// IP is simple, all zeroes.
	// The second case is trickier. First we need to find out the recipient's
	// IP. Since we have the clients hardware adress in the chaddr field of
	// the DHCP packet, this would most easily be done via ARP. The second is
	// trickier. We need somehow to get the source IP of the server. As to how,
	// I do not know…
	//
	// Both types of replies consists of an IP packet.
	iph = IPHeader{
		vhl:   0x45,
		tos:   0,
		id:    0x1234, // the kernel overwrites id if it is zero
		off:   0,
		ttl:   64,
		proto: unix.IPPROTO_UDP,
	}

	if dst_ip.Equal(net.IPv4bcast) {
		dst_hwaddr = ethernet.Broadcast
		copy(iph.src[:], net.IPv4zero.To4())
		copy(iph.dst[:], net.IPv4bcast.To4())
		// Length and checksum are calculated later.
	} else {
		fmt.Fprintf(os.Stdout, "%s\n", dst_ip.String())
		copy(iph.dst[:], dst_ip.To4())

		// haddr_ := packet.CHAddr()
		haddr, err := b.arpconn.Resolve(dst_ip)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ARP failure.")
			// return 0, nil
		}
		fmt.Fprintln(os.Stdout, haddr)
		dst_hwaddr = haddr
		// Find out some way to set the source IP
	}

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

	if dst_ip.Equal(net.IPv4bcast) {

		// Send it.
		addr := &raw.Addr{HardwareAddr: dst_hwaddr}
		return b.handle.WriteTo(g, addr)
	}

	// Vad som borde göras här är att göra en ARP-förfrågan och
	// konstruera ett ethernet-paket enligt ovan.

	fmt.Fprintln(os.Stdout, "This should be run.")
	return b.conn.WriteTo(p, b.cm, addr)
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

	// Open the device raw device for IP over ethernet
	config := &raw.Config{} // Ignored but needed on BSD
	h, err := raw.ListenPacket(ifi, 0x0800, config)
	if err != nil {
		// defer h.Close()
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	// Then set up a normal packet listener.
	l, err := net.ListenPacket("udp4", ":67")
	if err != nil {
		// defer l.Close()
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	p := ipv4.NewPacketConn(l)
	if err := p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return nil, err
	}

	// Set up an ARP-listener
	a, err := arp.Dial(ifi)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	return &BPFListener{Iface: ifi, handle: h, conn: p, iface: ifi, arpconn: a}, nil
	// return &BPFListener{Iface: ifi, handle: h, conn: p, iface: ifi}, nil

}
