//go:build !windows

package netmap

import (
	"net"
	"time"

	"tripsilk/internal/engine"
)

type Resolver struct{}

func NewResolver() *Resolver { return &Resolver{} }

// Scan is Windows-only for now; the Linux collector (eBPF or /proc/net/tcp)
// is the VPS milestone.
func Scan(r *Resolver) ([]Flow, error) { return nil, engine.ErrUnsupported }

type Conn struct {
	PID    uint32
	Remote string
}

func Connections() ([]Conn, error)                    { return nil, engine.ErrUnsupported }
func ProcessNames() (map[uint32]string, error)        { return nil, engine.ErrUnsupported }
func (r *Resolver) Refresh(maxAge time.Duration)      {}
func (r *Resolver) SetPassive(on bool)                {}
func (r *Resolver) Lookup(ip net.IP) string           { return "" }
func (r *Resolver) Learn(name string, addrs []net.IP) {}
func (r *Resolver) RefreshCache(maxAge time.Duration) {}
func (r *Resolver) CachedCount() int                  { return 0 }
func (r *Resolver) ResolvedCount() int                { return 0 }

func ScanAll(r *Resolver) ([]LiveConn, error) { return nil, engine.ErrUnsupported }
func Listeners() ([]Listener, error)          { return nil, engine.ErrUnsupported }
func (r *Resolver) HostCount() int            { return 0 }
func (r *Resolver) Host(ip net.IP) string     { return "" }
