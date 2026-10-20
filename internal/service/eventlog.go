package service

import (
	"sync/atomic"

	"tripsilk/internal/engine"
	"tripsilk/internal/eventlog"
)

// Copying alerts into the Windows Event Log (week 4), for specialists'
// tools. Off by default: Settings turns it on.

type evlogState struct {
	w    atomic.Pointer[eventlog.Writer]
	errs atomic.Int64
	last atomic.Pointer[string]
}

// startEventLog opens the writer when the setting is on, and copies every
// alert while it's open. The subscriber takes no Service locks: detectors
// publish while holding s.mu.
func (s *Service) startEventLog() {
	if s.store.Get().EventLogCopy {
		if err := s.openEventLog(); err != nil {
			s.Bus.Publish(engine.Alert{Severity: engine.SevLow, Source: "system", Title: "Alerts aren't being copied to the Event Log",
				Detail: err.Error() + ". Turn the setting off and on again in Settings to retry."})
		}
	}
	s.Bus.Subscribe(func(a engine.Alert) {
		w := s.ev.w.Load()
		if w == nil || a.Severity == engine.SevInfo {
			return
		}
		if err := w.Write(a); err != nil {
			s.ev.errs.Add(1)
			msg := err.Error()
			s.ev.last.Store(&msg)
		}
	})
}

func (s *Service) openEventLog() error {
	if err := eventlog.Register(); err != nil {
		return err
	}
	w, err := eventlog.Open()
	if err != nil {
		return err
	}
	if old := s.ev.w.Swap(w); old != nil {
		old.Close()
	}
	return nil
}

// SetEventLog turns copying alerts to the Event Log on or off. Off also
// removes Tripsilk's event source; events already written stay.
func (s *Service) SetEventLog(on bool) error {
	if on {
		if err := s.openEventLog(); err != nil {
			return err
		}
	} else {
		if w := s.ev.w.Swap(nil); w != nil {
			w.Close()
		}
		if err := eventlog.Unregister(); err != nil {
			return err
		}
	}
	if err := s.store.Update(func(c *engine.Config) { c.EventLogCopy = on }); err != nil {
		return err
	}
	if on {
		s.note("Copying alerts to the Event Log", "Application log, source Tripsilk. Event IDs: 1001 trip line, 1002 ransomware shield, 1003 agent, 1004 burst, 1005 internet lock, 1006 control channel.")
	}
	return nil
}

// EventLogStatus is shown in Settings.
type EventLogStatus struct {
	On      bool   `json:"on"`
	Open    bool   `json:"open"`
	Errors  int64  `json:"errors"`
	LastErr string `json:"lastError,omitempty"`
}

func (s *Service) eventLogStatus(on bool) EventLogStatus {
	st := EventLogStatus{On: on, Open: s.ev.w.Load() != nil, Errors: s.ev.errs.Load()}
	if p := s.ev.last.Load(); p != nil {
		st.LastErr = *p
	}
	return st
}
