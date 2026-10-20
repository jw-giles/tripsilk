//go:build windows

package netmap

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"tripsilk/internal/win"
)

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afInet               = 2
	afInet6              = 23
	tcpTableOwnerPidConn = 4 // TCP_TABLE_OWNER_PID_CONNECTIONS: established etc., no listeners
	tcpTableOwnerPidLsn  = 3 // TCP_TABLE_OWNER_PID_LISTENER
	errInsufficientBuf   = 122
)

// tcpRow mirrors MIB_TCPROW_OWNER_PID.
type tcpRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// tcp6Row mirrors MIB_TCP6ROW_OWNER_PID.
type tcp6Row struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

type conn struct {
	pid    uint32
	state  uint32
	remote net.IP
	port   uint16
}

// TCP states (MIB_TCP_STATE). Closed and TIME_WAIT rows linger after a
// connection ends and are owned by no real process (PID 0).
const (
	tcpStateClosed   = 1
	tcpStateTimeWait = 11
)

// live reports whether a row is a current connection owned by a real
// process. PID 0 (idle) and 4 (System kernel) never make AI calls; their
// rows are leftovers from connections other programs already closed.
func (c conn) live() bool {
	return c.pid > 4 && c.state != tcpStateClosed && c.state != tcpStateTimeWait
}

// netPort converts a port stored in network byte order in the low 16 bits.
func netPort(v uint32) uint16 { return uint16(v&0xff)<<8 | uint16(v>>8&0xff) }

// tcpTable fetches one address family's connection table.
func tcpTable(af uintptr) ([]byte, uint32, error) { return tcpTableClass(af, tcpTableOwnerPidConn) }

// tcpTableClass fetches one address family's table of the given class.
func tcpTableClass(af, class uintptr) ([]byte, uint32, error) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
	for attempt := 0; attempt < 4; attempt++ {
		size += 4096 // table can grow between calls
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
		if r == errInsufficientBuf {
			continue
		}
		if r != 0 {
			return nil, 0, fmt.Errorf("GetExtendedTcpTable(af=%d): error %d", af, r)
		}
		return buf, binary.LittleEndian.Uint32(buf[:4]), nil
	}
	return nil, 0, fmt.Errorf("GetExtendedTcpTable(af=%d): table kept growing", af)
}

// tcpConnections returns current IPv4 and IPv6 TCP connections with owning
// PIDs. An IPv6 failure (IPv6 disabled) is not fatal.
func tcpConnections() ([]conn, error) {
	buf, n, err := tcpTable(afInet)
	if err != nil {
		return nil, err
	}
	var out []conn
	rowSize := unsafe.Sizeof(tcpRow{})
	for i := uint32(0); i < n; i++ {
		off := 4 + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*tcpRow)(unsafe.Pointer(&buf[off]))
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, row.RemoteAddr)
		out = append(out, conn{pid: row.OwningPid, state: row.State, remote: ip, port: netPort(row.RemotePort)})
	}

	buf6, n6, err := tcpTable(afInet6)
	if err != nil {
		return out, nil
	}
	rowSize6 := unsafe.Sizeof(tcp6Row{})
	for i := uint32(0); i < n6; i++ {
		off := 4 + uintptr(i)*rowSize6
		if off+rowSize6 > uintptr(len(buf6)) {
			break
		}
		row := (*tcp6Row)(unsafe.Pointer(&buf6[off]))
		ip := make(net.IP, 16)
		copy(ip, row.RemoteAddr[:])
		out = append(out, conn{pid: row.OwningPid, state: row.State, remote: ip, port: netPort(row.RemotePort)})
	}
	return out, nil
}

// Resolver keeps an IP -> provider map by forward-resolving the catalog.
//
// Limitation, shown in the UI: providers behind shared CDNs (Cloudflare,
// Google front ends) share IPs with unrelated sites, so a match means
// "talking to an address that serves an LLM API", not proof of an LLM call.
type Resolver struct {
	mu        sync.RWMutex
	ips       map[string]string // from Tripsilk's own lookups
	cached    map[string]string // from the Windows DNS client cache and the sensor
	cachedAt  map[string]time.Time
	hosts     map[string]string // every cached address -> hostname
	refresh   time.Time
	cacheTime time.Time
	passive   bool // learn from the sensor's DNS answers; never look anything up
}

// passiveCacheAge is how often the DNS cache is re-read while the sensor runs.
const passiveCacheAge = 10 * time.Minute

// SetPassive stops Tripsilk's own DNS lookups. With the real-time sensor
// running, every answer any program on the PC receives is seen anyway (see
// Learn), so Tripsilk needs to send nothing itself.
func (r *Resolver) SetPassive(on bool) {
	r.mu.Lock()
	r.passive = on
	r.mu.Unlock()
}

// Learn records a DNS answer seen by the sensor: the name for each address,
// and the AI provider when the name belongs to one.
func (r *Resolver) Learn(name string, addrs []net.IP) {
	label := MatchProvider(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.hosts) > 20000 {
		r.hosts = map[string]string{}
	}
	for _, a := range addrs {
		r.hosts[a.String()] = name
		if label != "" {
			r.cached[a.String()] = label
			r.cachedAt[a.String()] = time.Now()
		}
	}
}

// labelKeep is how long an address stays labelled as an AI service after
// the last DNS answer that said so. Cloud addresses get reused by other
// customers; an agent that's still talking re-resolves well within a day.
const labelKeep = 24 * time.Hour

// pruneLabels drops stale labels. Caller holds r.mu.
func (r *Resolver) pruneLabels(now time.Time) {
	for ip, at := range r.cachedAt {
		if now.Sub(at) > labelKeep {
			delete(r.cached, ip)
			delete(r.cachedAt, ip)
		}
	}
}

func NewResolver() *Resolver {
	return &Resolver{ips: map[string]string{}, cached: map[string]string{}, cachedAt: map[string]time.Time{}, hosts: map[string]string{}}
}

// Refresh re-resolves provider hosts if the cache is older than maxAge.
func (r *Resolver) Refresh(maxAge time.Duration) {
	r.mu.RLock()
	fresh := time.Since(r.refresh) < maxAge || r.passive
	r.mu.RUnlock()
	if fresh {
		return
	}
	next := map[string]string{}
	for _, p := range Providers {
		// Prefix-style entries (bedrock-runtime) aren't resolvable hosts.
		if !strings.Contains(p.Suffix, ".") {
			continue
		}
		addrs, err := net.LookupIP(p.Suffix)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			next[a.String()] = p.Label
		}
	}
	r.mu.Lock()
	if len(next) > 0 { // keep the old map if DNS is down
		r.ips = next
	}
	r.refresh = time.Now()
	r.mu.Unlock()
}

// RefreshCache reads the Windows DNS client cache, which holds the exact
// addresses apps on this PC were given. CDNs rotate answers, so Tripsilk's own
// lookups alone often miss the address an app actually connected to.
func (r *Resolver) RefreshCache(maxAge time.Duration) {
	r.mu.RLock()
	if r.passive && maxAge < passiveCacheAge {
		// The sensor hands over every new DNS answer as it happens; the
		// cache only matters for lookups made before Tripsilk started, so
		// PowerShell isn't started every 30 seconds.
		maxAge = passiveCacheAge
	}
	fresh := time.Since(r.cacheTime) < maxAge
	r.mu.RUnlock()
	if fresh {
		return
	}
	out, err := win.PowerShell(30*time.Second, dnsCacheScript)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cacheTime = time.Now()
	r.pruneLabels(r.cacheTime)
	if err != nil {
		return
	}
	if h := ParseDNSHosts(out); h != nil {
		for ip, host := range h {
			r.hosts[ip] = host
		}
		if len(r.hosts) > 20000 {
			r.hosts = h
		}
	}
	if m := ParseDNSCache(out); m != nil {
		// Merge: a cache entry can expire while its connection stays open.
		for ip, label := range m {
			r.cached[ip] = label
			r.cachedAt[ip] = r.cacheTime
		}
		if len(r.cached) > 5000 {
			r.cached = m
			r.cachedAt = make(map[string]time.Time, len(m))
			for ip := range m {
				r.cachedAt[ip] = r.cacheTime
			}
		}
	}
}

func (r *Resolver) Lookup(ip net.IP) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if l := r.ips[ip.String()]; l != "" {
		return l
	}
	return r.cached[ip.String()]
}

// Scan returns current AI flows: remote provider connections plus running
// local model runtimes.
func Scan(r *Resolver) ([]Flow, error) {
	r.Refresh(10 * time.Minute)
	r.RefreshCache(30 * time.Second)
	var flows []Flow
	conns, err := tcpConnections()
	if err != nil {
		return nil, err
	}
	imageCache := map[uint32]string{}
	image := func(pid uint32) string {
		if s, ok := imageCache[pid]; ok {
			return s
		}
		s := win.ImagePath(pid)
		imageCache[pid] = s
		return s
	}
	for _, c := range conns {
		if !c.live() {
			continue
		}
		label := r.Lookup(c.remote)
		if label == "" {
			continue
		}
		flows = append(flows, Flow{
			PID:      c.pid,
			Image:    image(c.pid),
			Provider: label,
			Remote:   net.JoinHostPort(c.remote.String(), strconv.Itoa(int(c.port))),
		})
	}

	procs, err := listProcesses()
	if err == nil {
		for _, p := range procs {
			if label := MatchLocalRuntime(p.name); label != "" {
				flows = append(flows, Flow{
					PID:      p.pid,
					Image:    image(p.pid),
					Provider: label,
					Remote:   "local",
					Local:    true,
				})
			}
		}
	}
	return flows, nil
}

type procInfo struct {
	pid  uint32
	name string
}

func listProcesses() ([]procInfo, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snap)
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := syscall.Process32First(snap, &e); err != nil {
		return nil, err
	}
	var out []procInfo
	for {
		out = append(out, procInfo{pid: e.ProcessID, name: syscall.UTF16ToString(e.ExeFile[:])})
		if err := syscall.Process32Next(snap, &e); err != nil {
			break
		}
	}
	return out, nil
}

// Conn is an exported view of one TCP connection, for diagnostics.
type Conn struct {
	PID    uint32
	Remote string // ip:port
}

// Connections exposes the raw TCP table for the self-test.
func Connections() ([]Conn, error) {
	cs, err := tcpConnections()
	if err != nil {
		return nil, err
	}
	out := make([]Conn, len(cs))
	for i, c := range cs {
		out[i] = Conn{PID: c.pid, Remote: net.JoinHostPort(c.remote.String(), strconv.Itoa(int(c.port)))}
	}
	return out, nil
}

// ProcessNames exposes the process snapshot for the self-test.
func ProcessNames() (map[uint32]string, error) {
	ps, err := listProcesses()
	if err != nil {
		return nil, err
	}
	m := make(map[uint32]string, len(ps))
	for _, p := range ps {
		m[p.pid] = p.name
	}
	return m, nil
}

// ResolvedCount reports how many provider IPs are cached.
func (r *Resolver) ResolvedCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.ips) + len(r.cached)
}

// CachedCount reports provider addresses learned from the DNS client cache.
func (r *Resolver) CachedCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cached)
}

// Host names an address from the DNS cache, "" when unknown.
func (r *Resolver) Host(ip net.IP) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hosts[ip.String()]
}

// ScanAll returns every live connection, named where the DNS cache allows.
func ScanAll(r *Resolver) ([]LiveConn, error) {
	r.Refresh(10 * time.Minute)
	r.RefreshCache(30 * time.Second)
	conns, err := tcpConnections()
	if err != nil {
		return nil, err
	}
	out := make([]LiveConn, 0, len(conns))
	for _, c := range conns {
		if !c.live() || c.remote.IsLoopback() || c.remote.IsUnspecified() {
			continue
		}
		out = append(out, LiveConn{PID: c.pid, IP: c.remote.String(), Port: c.port,
			Host: r.Host(c.remote), AI: r.Lookup(c.remote)})
	}
	return out, nil
}

// Listeners returns programs accepting incoming TCP connections (IPv4 and
// IPv6). UDP is not covered yet.
func Listeners() ([]Listener, error) {
	var out []Listener
	images := map[uint32]string{}
	image := func(pid uint32) string {
		if s, ok := images[pid]; ok {
			return s
		}
		s := win.ImagePath(pid)
		images[pid] = s
		return s
	}
	buf, n, err := tcpTableClass(afInet, tcpTableOwnerPidLsn)
	if err != nil {
		return nil, err
	}
	rowSize := unsafe.Sizeof(tcpRow{})
	for i := uint32(0); i < n; i++ {
		off := 4 + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*tcpRow)(unsafe.Pointer(&buf[off]))
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, row.LocalAddr)
		out = append(out, Listener{PID: row.OwningPid, Image: image(row.OwningPid),
			Port: netPort(row.LocalPort), Addr: ip.String(), Exposed: !ip.IsLoopback()})
	}
	if buf6, n6, err := tcpTableClass(afInet6, tcpTableOwnerPidLsn); err == nil {
		rowSize6 := unsafe.Sizeof(tcp6Row{})
		for i := uint32(0); i < n6; i++ {
			off := 4 + uintptr(i)*rowSize6
			if off+rowSize6 > uintptr(len(buf6)) {
				break
			}
			row := (*tcp6Row)(unsafe.Pointer(&buf6[off]))
			ip := make(net.IP, 16)
			copy(ip, row.LocalAddr[:])
			out = append(out, Listener{PID: row.OwningPid, Image: image(row.OwningPid),
				Port: netPort(row.LocalPort), Addr: ip.String(), Exposed: !ip.IsLoopback()})
		}
	}
	return out, nil
}

// HostCount reports how many cached addresses have names.
func (r *Resolver) HostCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.hosts)
}
