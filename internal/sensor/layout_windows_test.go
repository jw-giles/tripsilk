//go:build windows && amd64

package sensor

import (
	"testing"
	"unsafe"
)

// The Windows SDK sizes on x64. A wrong size here means Windows reads or
// writes the wrong memory, so these are checked on every build.
func TestLayouts(t *testing.T) {
	cases := []struct {
		name      string
		got, want uintptr
	}{
		{"WNODE_HEADER", unsafe.Sizeof(wnodeHeader{}), 48},
		{"EVENT_TRACE_PROPERTIES", unsafe.Sizeof(eventTraceProperties{}), 120},
		{"EVENT_DESCRIPTOR", unsafe.Sizeof(eventDescriptor{}), 16},
		{"EVENT_HEADER", unsafe.Sizeof(eventHeader{}), 80},
		{"EVENT_RECORD", unsafe.Sizeof(eventRecord{}), 112},
		{"EVENT_TRACE_LOGFILEW", unsafe.Sizeof(eventTraceLogfile{}), 448},
		{"EVENT_FILTER_DESCRIPTOR", unsafe.Sizeof(eventFilterDescriptor{}), 16},
		{"ENABLE_TRACE_PARAMETERS", unsafe.Sizeof(enableTraceParameters{}), 48},
		{"GUID", unsafe.Sizeof(GUID{}), 16},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: size %d, want %d", c.name, c.got, c.want)
		}
	}
	var r eventRecord
	if off := unsafe.Offsetof(r.UserDataLength); off != 86 {
		t.Errorf("EVENT_RECORD.UserDataLength at %d, want 86", off)
	}
	if off := unsafe.Offsetof(r.UserData); off != 96 {
		t.Errorf("EVENT_RECORD.UserData at %d, want 96", off)
	}
	var lf eventTraceLogfile
	if off := unsafe.Offsetof(lf.EventCallback); off != 424 {
		t.Errorf("EVENT_TRACE_LOGFILEW.EventRecordCallback at %d, want 424", off)
	}
	var h eventHeader
	if off := unsafe.Offsetof(h.EventDescriptor); off != 40 {
		t.Errorf("EVENT_HEADER.EventDescriptor at %d, want 40", off)
	}
}
