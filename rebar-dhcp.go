// +build !openbsd

package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
	"gopkg.in/gcfg.v1"
)

type Config struct {
	Network struct {
		Port     int
		Username string
		Password string
	}
}

var ignore_anonymus bool
var config_path, socket_path, data_dir, ifi string

func init() {
	flag.StringVar(&config_path, "config_path", "/etc/rebar-dhcp.conf", "Path to config file")
	flag.StringVar(&socket_path, "socket_path", "/var/run/dhcpd.sock", "Path to FCGI-socket")
	flag.StringVar(&data_dir, "data_dir", "/var/cache/rebar-dhcp", "Path to store data")
	flag.StringVar(&ifi, "interface", "em0", "Network interface to listen on")
	flag.BoolVar(&ignore_anonymus, "ignore_anonymus", false, "Ignore unknown MAC addresses")
}

func main() {
	flag.Parse()

	var cfg Config
	cerr := gcfg.ReadFileInto(&cfg, config_path)
	if cerr != nil {
		fmt.Fprintln(os.Stderr, cerr)
		os.Exit(1)
	}
	fs, err := NewFileStore(data_dir + "/database.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	tracker := NewDataTracker(fs)
	tracker.load_data()

	fe, err := NewFrontend(socket_path, cfg, tracker)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Varför behöver “listener” egentligen namnet på nätverksgränssnittet?
	// Vi har redan en pekare *iface.
	// Egentligen är ju lösningen även här att skita i hur FilterListener beter
	// sig och låta BPFListener ha ett publikt attribut “Iface”. Då lyssnaren
	// redan skickas vidare som argument överallt så…
	listener, err := NewBPFListener(ifi)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Här borde man kunna kasta bort alla privilegier.
	// Men det kan man inte, för av någon anledning går
	// det inte att spara data då…

	go RunDhcpHandler(tracker, listener)

	fe.RunServer(true)

	// Men här går det även om det känns lite “för sent”…
	uid, _ := user.Lookup("nobody")
	gid, _ := user.LookupGroup("nogroup")
	gid_int, _ := strconv.Atoi(gid.Gid)
	uid_int, _ := strconv.Atoi(uid.Uid)

	// Om man inte sätter uid först så har man inga rättigheter
	// för att sätta gid.
	err = unix.Setgid(gid_int)
	err = unix.Setuid(uid_int)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

}
