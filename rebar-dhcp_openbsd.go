package main

import (
	"flag"
	"fmt"
	"net"
	"os"

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
	flag.StringVar(&socket_path, "socket_path", "9002", "FCGI-socket listening port")
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

	sock, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%s", socket_path))

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fe := NewFrontend(sock, cfg, tracker)

	listener, err := NewBPFListener(ifi)

	err = unix.Unveil("/var/cache/rebar-dhcp", "rwc")
	// err = unix.Unveil(socket_path, "rwc")
	err = unix.UnveilBlock()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't block filesystem access, exiting.")
		os.Exit(1)
	}
	// Sådär då, nu kan processen enbart läsa/skriva till
	// lånedatabasen samt en sockel.

	// Här borde man kunna kasta bort alla privilegier.
	// Men det kan man inte, för av någon anledning går
	// det inte att spara data då…
	// Och anledningen är att idiomatisk Go inte verkar
	// vara att öppna en fil för att sedan skriva/läsa/skriva
	// utan att öppna den var gång. Det ställer till problem
	// då filen/databasen ägs av root.

	go RunDhcpHandler(tracker, listener)

	// err := unix.Pledge("stdio", "")
	// if err != nil {
	//     fmt.Println("Couldn't pledge, exiting.")
	//     os.Exit(1)
	// }

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	err = fe.RunServer(true) // Hantera ev. fel

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
