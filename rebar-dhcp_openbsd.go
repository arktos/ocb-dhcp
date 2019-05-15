package main

import (
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"gopkg.in/gcfg.v1"
	"os"
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

	fe := NewFrontend(cert_pem, key_pem, cfg, fs)
	listener, err := NewBPFListener(ifi)

	err = unix.Unveil("/var/cache/rebar-dhcp", "rwc")
	err = unix.UnveilBlock()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't block filesystem access, exiting.")
		os.Exit(1)
	}
	// Sådär då, nu kan processen enbart läsa/skriva till en
	// specifik fil.

	// Här borde man kunna kasta bort alla privilegier.
	// Men det kan man inte, för av någon anledning går
	// det inte att spara data då…
	// Och anledningen är att idiomatisk Go inte verkar
	// vara att öppna en fil för att sedan skriva/läsa/skriva
	// utan att öppna den var gång. Det ställer till problem
	// då filen/databasen ägs av root.

	go RunDhcpHandler(fe.Tracker, listener, ifi)

	// Men här går det även om det känns lite “för sent”…
	// uid, _ := user.Lookup("nobody")
	// gid, _ := user.LookupGroup("nogroup")
	// gid_int, _ := strconv.Atoi(gid.Gid)
	// uid_int, _ := strconv.Atoi(uid.Uid)

	// Om man inte sätter uid först så har man inga rättigheter
	// för att sätta gid.
	// err = unix.Setgid(gid_int)
	// err = unix.Setuid(uid_int)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fe.RunServer(true)
}
