package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ant0ine/go-json-rest/rest"
	dhcp "github.com/krolaw/dhcp4"
)

/*
 * Managment API Structures
 *
 * These are the management API structures
 *
 * These match the json objects that are needed to
 * update/create and get subnets information and records
 *
 * Includes bind and unbind actions.
 */
type ApiSubnet struct {
	Name              string     `json:"name"`
	Subnet            string     `json:"subnet"`
	NextServer        *string    `json:"next_server,omitempty"`
	ActiveStart       string     `json:"active_start"`
	ActiveEnd         string     `json:"active_end"`
	ActiveLeaseTime   int        `json:"active_lease_time"`
	ReservedLeaseTime int        `json:"reserved_lease_time"`
	Leases            []*Lease   `json:"leases,omitempty"`
	Bindings          []*Binding `json:"bindings,omitempty"`
	Options           []*Option  `json:"options,omitempty"`
}

// Option id number from DHCP RFC 2132 and 2131
// Value is a string version of the value
type Option struct {
	Code  dhcp.OptionCode `json:"id"`
	Value string          `json:"value"`
}

type Lease struct {
	Ip         net.IP    `json:"ip"`
	Mac        string    `json:"mac"`
	Valid      bool      `json:"valid"`
	ExpireTime time.Time `json:"expire_time"`
	Hostname   string    `json:"hostname,omitempty"`
}

type Binding struct {
	Ip         net.IP    `json:"ip"`
	Mac        string    `json:"mac"`
	Options    []*Option `json:"options,omitempty"`
	NextServer *string   `json:"next_server,omitempty"`
}

type NextServer struct {
	Server string `json:"next_server"`
}

func NewApiSubnet() *ApiSubnet {
	return &ApiSubnet{
		Leases:   make([]*Lease, 0),
		Bindings: make([]*Binding, 0),
		Options:  make([]*Option, 0),
	}
}

func NewBinding() *Binding {
	return &Binding{
		Options: make([]*Option, 0),
	}
}

/*
 * Structure for the front end with a pointer to the backend
 */
type Frontend struct {
	DhcpInfo *DataTracker
	data_dir string
	cert_pem string
	key_pem  string
	cfg      Config
}

func NewFrontend(cert_pem, key_pem string, cfg Config, store LoadSaver) *Frontend {
	fe := &Frontend{
		data_dir: data_dir,
		cert_pem: cert_pem,
		key_pem:  key_pem,
		cfg:      cfg,
		DhcpInfo: NewDataTracker(store),
	}

	fe.DhcpInfo.load_data()

	return fe
}

// List function
func (fe *Frontend) GetAllSubnets(w rest.ResponseWriter, r *rest.Request) {
	nets := make([]*ApiSubnet, 0)

	for _, s := range fe.DhcpInfo.Subnets {
		as := convertSubnetToApiSubnet(s)
		nets = append(nets, as)
	}

	w.WriteJson(nets)
}

// Get function
func (fe *Frontend) GetSubnet(w rest.ResponseWriter, r *rest.Request) {
	subnetName := r.PathParam("id")

	subnet := fe.DhcpInfo.Subnets[subnetName]
	if subnet == nil {
		rest.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	w.WriteJson(convertSubnetToApiSubnet(subnet))
}

// Create function
func (fe *Frontend) CreateSubnet(w rest.ResponseWriter, r *rest.Request) {
	apisubnet := NewApiSubnet()
	if r.Body != nil {
		err := r.DecodeJsonPayload(&apisubnet)
		if err != nil {
			rest.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		rest.Error(w, "Must have body", http.StatusBadRequest)
		return
	}

	subnet, err := convertApiSubnetToSubnet(apisubnet, nil)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err, code := fe.DhcpInfo.AddSubnet(subnet)
	if err != nil {
		rest.Error(w, err.Error(), code)
		return
	}

	w.WriteJson(apisubnet)
}

// Update function
func (fe *Frontend) UpdateSubnet(w rest.ResponseWriter, r *rest.Request) {
	subnetName := r.PathParam("id")
	apisubnet := NewApiSubnet()
	if r.Body != nil {
		err := r.DecodeJsonPayload(&apisubnet)
		if err != nil {
			rest.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		rest.Error(w, "Must have body", http.StatusBadRequest)
		return
	}

	subnet, err := convertApiSubnetToSubnet(apisubnet, nil)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err, code := fe.DhcpInfo.ReplaceSubnet(subnetName, subnet)
	if err != nil {
		rest.Error(w, err.Error(), code)
		return
	}

	w.WriteJson(apisubnet)
}

// Delete function
func (fe *Frontend) DeleteSubnet(w rest.ResponseWriter, r *rest.Request) {
	subnetName := r.PathParam("id")

	err, code := fe.DhcpInfo.RemoveSubnet(subnetName)
	if err != nil {
		rest.Error(w, err.Error(), code)
		return
	}

	w.WriteHeader(code)
}

func (fe *Frontend) BindSubnet(w rest.ResponseWriter, r *rest.Request) {
	subnetName := r.PathParam("id")
	binding := Binding{}
	if r.Body != nil {
		err := r.DecodeJsonPayload(&binding)
		if err != nil {
			rest.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		rest.Error(w, "Must have body", http.StatusBadRequest)
		return
	}

	err, code := fe.DhcpInfo.AddBinding(subnetName, binding)
	if err != nil {
		rest.Error(w, err.Error(), code)
		return
	}

	w.WriteJson(binding)
}

func (fe *Frontend) UnbindSubnet(w rest.ResponseWriter, r *rest.Request) {
	subnetName := r.PathParam("id")
	mac := r.PathParam("mac")

	err, code := fe.DhcpInfo.DeleteBinding(subnetName, mac)
	if err != nil {
		rest.Error(w, err.Error(), code)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (fe *Frontend) NextServer(w rest.ResponseWriter, r *rest.Request) {
	subnetName := r.PathParam("id")
	nextServer := NextServer{}
	if r.Body != nil {
		err := r.DecodeJsonPayload(&nextServer)
		if err != nil {
			rest.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		rest.Error(w, "Must have body", http.StatusBadRequest)
		return
	}

	ip := net.ParseIP(r.PathParam("ip"))

	err, code := fe.DhcpInfo.SetNextServer(subnetName, ip, nextServer)
	if err != nil {
		rest.Error(w, err.Error(), code)
		return
	}

	w.WriteJson(nextServer)
}

func (fe *Frontend) GetChaddr(w rest.ResponseWriter, r *rest.Request) {
	// Skulle behöva läsa på lite om
	// https://github.com/ant0ine/go-json-rest
	// Behövs nämligen två parametrar: subnet och chaddr.
	subnetName := r.PathParam("id")
	chaddr := r.PathParam("mac")

	fmt.Println(chaddr)
	// Verkar som om ingen annan funktion låser subnätet, kanske inte jag heller
	// behöver göra det? Jag prövar, det kan ju gå…
	subnet := fe.DhcpInfo.Subnets[subnetName]
	if subnet == nil {
		rest.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Om jag läser koden rätt så är subnet.Leases en karta med en sträng
	// motsvarande en MAC som nyckel och en pekare till ett lån som värde.
	// Enda problemet här är väl hur strängen skall se ut?
	l, ok := subnet.Leases[chaddr]
	if !ok {
		rest.Error(w, "Not Found", http.StatusNotFound)
	}

	fmt.Println(*l)
	// Okej, vi har nu ett lån. Vilken datastruktur i go går att konvertera
	// till JSON på formen {'mac': 'blablabla', 'ip': '10.0.0.1'}?
	// Enklaste är väl att helt enkelt använda en Struct Lease{}?
	// Låt vara att den kanske läcker lite information, men är man redan
	// här och rotar så…
	w.WriteJson(*l)
}

func (fe *Frontend) RunServer(blocking bool, certs *tls.Config) {
	api := rest.NewApi()
	api.Use(&rest.AuthBasicMiddleware{
		Realm: "test zone",
		Authenticator: func(userId string, password string) bool {
			if userId == fe.cfg.Network.Username &&
				password == fe.cfg.Network.Password {
				return true
			}
			return false
		},
	})
	api.Use(rest.DefaultDevStack...)
	router, err := rest.MakeRouter(
		rest.Get("/subnets", fe.GetAllSubnets),
		rest.Get("/subnets/#id", fe.GetSubnet),
		rest.Get("/subnets/#id/#mac", fe.GetChaddr),
		rest.Post("/subnets", fe.CreateSubnet),
		rest.Put("/subnets/#id", fe.UpdateSubnet),
		rest.Delete("/subnets/#id", fe.DeleteSubnet),
		rest.Post("/subnets/#id/bind", fe.BindSubnet),
		rest.Delete("/subnets/#id/bind/#mac", fe.UnbindSubnet),
		rest.Put("/subnets/#id/next_server/#ip", fe.NextServer),
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	api.SetApp(router)

	connStr := fmt.Sprintf(":%d", fe.cfg.Network.Port)
	fmt.Println("Web Interface Using", connStr)

	server := http.Server{
		Addr:      connStr,
		Handler:   api.MakeHandler(),
		TLSConfig: certs,
	}

	defer server.Close()
	e := server.ListenAndServeTLS("", "")
	// e := http.ListenAndServeTLS(connStr, fe.cert_pem, fe.key_pem, api.MakeHandler())
	if e != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
