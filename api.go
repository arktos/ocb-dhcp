package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/url"
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
	Tracker     *DataTracker
	data_dir    string
	socket_path string
	cfg         Config
}

func NewFrontend(socket string, cfg Config, store *DataTracker) *Frontend {
	fe := &Frontend{
		data_dir:    data_dir,
		socket_path: socket,
		cfg:         cfg,
		Tracker:     store,
	}
	return fe
}

// List function
func (fe *Frontend) GetAllSubnets(w rest.ResponseWriter, r *rest.Request) {
	nets := make([]*ApiSubnet, 0)

	for _, s := range fe.Tracker.Subnets {
		as := convertSubnetToApiSubnet(s)
		nets = append(nets, as)
	}

	w.WriteJson(nets)
}

// Get function
func (fe *Frontend) GetSubnet(w rest.ResponseWriter, r *rest.Request) {
	subnetName := r.PathParam("id")

	subnet := fe.Tracker.Subnets[subnetName]
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

	err, code := fe.Tracker.AddSubnet(subnet)
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

	err, code := fe.Tracker.ReplaceSubnet(subnetName, subnet)
	if err != nil {
		rest.Error(w, err.Error(), code)
		return
	}

	w.WriteJson(apisubnet)
}

// Delete function
func (fe *Frontend) DeleteSubnet(w rest.ResponseWriter, r *rest.Request) {
	subnetName := r.PathParam("id")

	err, code := fe.Tracker.RemoveSubnet(subnetName)
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

	err, code := fe.Tracker.AddBinding(subnetName, binding)
	if err != nil {
		rest.Error(w, err.Error(), code)
		return
	}

	w.WriteJson(binding)
}

func (fe *Frontend) UnbindSubnet(w rest.ResponseWriter, r *rest.Request) {
	subnetName := r.PathParam("id")
	mac := r.PathParam("mac")

	err, code := fe.Tracker.DeleteBinding(subnetName, mac)
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

	err, code := fe.Tracker.SetNextServer(subnetName, ip, nextServer)
	if err != nil {
		rest.Error(w, err.Error(), code)
		return
	}

	w.WriteJson(nextServer)
}

func (fe *Frontend) GetChaddr(w rest.ResponseWriter, r *rest.Request) {
	leases := make([]*Lease, 0)
	chaddr, _ := url.QueryUnescape(r.PathParam("mac"))

	// Onödigt dyrt att köra gång på gång i en slinga.
	t := time.Now()
	for _, v := range fe.Tracker.Subnets {

		// Om jag läser koden rätt så är subnet.Leases en karta med en sträng
		// motsvarande en MAC som nyckel och en pekare till ett lån som värde.
		// Enda problemet här är väl hur strängen skall se ut?
		// Nu fungerar enbart ett värde på formen aa:aa:aa:aa:aa:aa.
		l, ok := v.Leases[chaddr]
		if !ok {
			continue
		}
		if !(l.ExpireTime.After(t)) {
			// if !valid {
			continue
		}
		leases = append(leases, l)
	}

	if len(leases) > 0 {
		w.WriteJson(leases)
	} else {
		rest.Error(w, "Not Found", http.StatusNotFound)
	}
}

func (fe *Frontend) RunServer(blocking bool) {
	api := rest.NewApi()
	api.Use(rest.DefaultDevStack...)
	router, err := rest.MakeRouter(
		rest.Get("/subnets", fe.GetAllSubnets),
		rest.Get("/subnets/#id", fe.GetSubnet),
		rest.Get("/chaddr/#mac", fe.GetChaddr),
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

	if e := os.RemoveAll(fe.socket_path); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}

	listener, err := net.Listen("unix", fe.socket_path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	defer listener.Close()
	defer func() {
		os.Remove(fe.socket_path)
	}()

	if e := os.Chown(fe.socket_path, -1, 67); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}

	if e := os.Chmod(fe.socket_path, 660); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}

	fmt.Println("Web Interface Using", fe.socket_path)
	if e := fcgi.Serve(listener, http.StripPrefix("/dhcp", api.MakeHandler())); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
