package zap

import (
	"encoding/json"
	"testing"
)

func TestAlertsFromReport(t *testing.T) {
	const rep = `{"@version":"2.15","site":[{"alerts":[{"pluginid":"10020","alert":"X-Frame-Options Header Not Set","riskdesc":"Medium (Medium)","confidence":"Medium","instances":[{"uri":"a"},{"uri":"b"}]}]}]}`
	var m map[string]any
	if err := json.Unmarshal([]byte(rep), &m); err != nil {
		t.Fatal(err)
	}
	alerts := AlertsFromReport(m, "https://h")
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d", len(alerts))
	}
	a := alerts[0]
	if a.PluginID != "10020" || a.InstancesCount != 2 || a.Risk != "Medium (Medium)" || a.Target != "https://h" {
		t.Errorf("alert = %+v", a)
	}
	// A single site object (not a list) is also accepted.
	m["site"] = m["site"].([]any)[0]
	if got := AlertsFromReport(m, "t"); len(got) != 1 {
		t.Errorf("single-site report: %d alerts", len(got))
	}
}
