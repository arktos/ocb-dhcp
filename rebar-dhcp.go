// +build !openbsd

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"gopkg.in/gcfg.v1"
	"net"
	"os"
	"os/user"
	"strconv"
)

type Config struct {
	Network struct {
		Port     int
		Username string
		Password string
	}
}

var ignore_anonymus bool
var config_path, key_pem, cert_pem, data_dir string
var ifi string

func init() {
	flag.StringVar(&config_path, "config_path", "/etc/rebar-dhcp.conf", "Path to config file")
	flag.StringVar(&key_pem, "key_pem", "/etc/dhcp-https-key.pem", "Path to key file")
	flag.StringVar(&cert_pem, "cert_pem", "/etc/dhcp-https-cert.pem", "Path to cert file")
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

	iface, err := net.InterfaceByName(ifi)
	if err != nil {
		fmt.Fprintln(os.Stderr, "No interface by that name.")
	}

	certs, _ := tls.LoadX509KeyPair(cert_pem, key_pem)
	tls_cfg := &tls.Config{Certificates: []tls.Certificate{certs}}
	fe := NewFrontend(certs, cfg, tracker)

	// Det här är en av två saker som kräver extra privilegier, den andra
	// är NewBPFListener() som anropas av RunDHCPHandler i dhcp.go. Kunde
	// man initialisera bägge här skulle man kunna kasta bort alla extra
	// privilegier efter denna rad.
	// Anropskedjan som är intressant ser ut som:
	// StartDhcpHandlers() -> RunDHCPHandler() -> NewBPFListener()

	// Varför behöver “listener” egentligen namnet på nätverksgränssnittet?
	// Vi har redan en pekare *iface.
	// Egentligen är ju lösningen även här att skita i hur FilterListener beter
	// sig och låta BPFListener ha ett publikt attribut “Iface”. Då lyssnaren
	// redan skickas vidare som argument överallt så…
	listener, err := NewBPFListener(ifi)

	// Här borde man kunna kasta bort alla privilegier.
	// Men det kan man inte, för av någon anledning går
	// det inte att spara data då…

	go RunDhcpHandler(tracker, iface, listener)

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

	fe.RunServer(true)
}
