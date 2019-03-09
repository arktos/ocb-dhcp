// +build !openbsd

package main

import (
	"fmt"
	dhcp "github.com/krolaw/dhcp4"
	"log"
	"net"
	"os"
)

func RunDhcpHandler(tracker *DataTracker, intf *net.Interface, listener *conn.BPFListener) error {
	var siaddr net.IP

	addrs, err := intf.Addrs()
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		thisIP, _, _ := net.ParseCIDR(addr.String())
		// Only care about addresses that are not link-local.
		if !thisIP.IsGlobalUnicast() {
			continue
		}
		// Only deal with IPv4 for now.
		if thisIP.To4() == nil {
			continue
		}
		// Spelar egentligen ingen roll vilken address man använder
		// för siaddr. Det enda viktiga är att den är unik.
		siaddr = thisIP
		break
	}

	fmt.Fprintln(os.Stdout, "Starting on interface: ", intf.Name)

	// serverIP, _, _ := net.ParseCIDR(sip)
	handler := &DHCPHandler{
		ip:   siaddr.To4(),
		intf: *intf,
		info: tracker,
	}
	log.Fatal(dhcp.Serve(listener, handler))
	return nil
}

type DHCPHandler struct {
	intf net.Interface // Interface processing on.
	ip   net.IP        // Server IP to use
	info *DataTracker  // Subnet data
}

func (h *DHCPHandler) ServeDHCP(p dhcp.Packet, msgType dhcp.MessageType, options dhcp.Options) (d dhcp.Packet) {

	// First find the subnet to use. giaddr field to lookup subnet if not all zeros.
	// If all zeros, use the interfaces Addrs to find a subnet, first wins.
	var subnet *Subnet
	subnet = nil

	giaddr := p.GIAddr()
	if !giaddr.Equal(net.IPv4zero) {
		fmt.Fprintln(os.Stdout, "Received unicast message on ", h.intf.Name)
		subnet = h.info.FindSubnet(giaddr)
	} else {
		fmt.Fprintln(os.Stdout, "Received Broadcast/Local message on ", h.intf.Name)
		addrs, err := h.intf.Addrs()
		if err != nil {
			fmt.Fprintln(os.Stdout, "Can't find addresses for ", h.intf.Name, ": ", err)
		}

		for _, a := range addrs {
			aip, _, _ := net.ParseCIDR(a.String())

			// Only operate on v4 addresses
			if aip.To4() == nil {
				continue
			}

			subnet = h.info.FindSubnet(aip)
			if subnet != nil {
				break
			}

		}

		if ignore_anonymus {
			// Search all subnets for a binding. First wins
			fmt.Fprintln(os.Stdout, "Looking up bound subnet for ", p.CHAddr().String())
			subnet = h.info.FindBoundIP(p.CHAddr())
		}

		if subnet == nil {
			// We didn't find a subnet for the interface.  Look for the assigned server IP
			subnet = h.info.FindSubnet(h.ip)
		}

	}

	if subnet == nil {
		fmt.Fprintln(os.Stdout, "Can not find subnet for packet, ignoring")
		return
	}

	nic := p.CHAddr().String()
	hostname := string(options[dhcp.OptionHostName])
	switch msgType {

	case dhcp.Discover:
		lease, binding := subnet.find_or_get_info(h.info, nic, p.CIAddr(), hostname)
		if lease == nil {
			fmt.Fprintln(os.Stdout, "Out of IPs for ", subnet.Name, ", ignoring")
			return nil
		}
		// Ignore unknown MAC address
		if ignore_anonymus && binding == nil {
			fmt.Fprintln(os.Stdout, "Ignoring request from unknown MAC address")
			return dhcp.ReplyPacket(p, dhcp.NAK, h.ip, nil, 0, nil)
		}

		options, lease_time := subnet.build_options(lease, binding)

		reply := dhcp.ReplyPacket(p, dhcp.Offer,
			h.ip,
			lease.Ip,
			lease_time,
			subnet.Options.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))
		fmt.Fprintln(os.Stdout, "Discover: Handing out: ", reply.YIAddr(), " to ", reply.CHAddr())
		return reply

	case dhcp.Request:
		server, ok := options[dhcp.OptionServerIdentifier]
		if ok && !net.IP(server).Equal(h.ip) {
			return nil // Message not for this dhcp server
		}
		reqIP := net.IP(options[dhcp.OptionRequestedIPAddress])
		if reqIP == nil {
			reqIP = net.IP(p.CIAddr())
		}

		if len(reqIP) != 4 || reqIP.Equal(net.IPv4zero) {
			return dhcp.ReplyPacket(p, dhcp.NAK, h.ip, nil, 0, nil)
		}

		lease, binding := subnet.find_info(h.info, nic)
		// Ignore unknown MAC address
		if ignore_anonymus && binding == nil {
			fmt.Fprintln(os.Stdout, "Ignoring request from unknown MAC address")
			return dhcp.ReplyPacket(p, dhcp.NAK, h.ip, nil, 0, nil)
		}
		if lease == nil || !lease.Ip.Equal(reqIP) {
			return dhcp.ReplyPacket(p, dhcp.NAK, h.ip, nil, 0, nil)
		}

		options, lease_time := subnet.build_options(lease, binding)

		subnet.update_lease_time(h.info, lease, lease_time)

		reply := dhcp.ReplyPacket(p, dhcp.ACK,
			h.ip,
			lease.Ip,
			lease_time,
			subnet.Options.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))
		if binding != nil && binding.NextServer != nil {
			reply.SetSIAddr(net.ParseIP(*binding.NextServer))
		} else if subnet.NextServer != nil {
			reply.SetSIAddr(*subnet.NextServer)
		}
		fmt.Fprintln(os.Stdout, "Request: Handing out: ", reply.YIAddr(), " to ", reply.CHAddr())
		return reply

	case dhcp.Release, dhcp.Decline:
		nic := p.CHAddr().String()
		subnet.free_lease(h.info, nic)
	}
	return nil
}
