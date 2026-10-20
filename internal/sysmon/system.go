package sysmon

import "encoding/xml"

// parseSystem reads just the System part (for record IDs of events Parse
// skips).
func parseSystem(raw string, x *xmlEvent) (error, bool) {
	if err := xml.Unmarshal([]byte(raw), x); err != nil {
		return err, false
	}
	return nil, true
}
