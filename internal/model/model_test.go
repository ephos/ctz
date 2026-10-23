package model

import (
	"encoding/json"
	"testing"
)

func TestOrderedPreservesOrder(t *testing.T) {
	o := NewOrdered[int]()
	o.Set("b", 1)
	o.Set("a", 2)
	o.Set("b", 3)
	data, err := json.Marshal(o)
	if err != nil || string(data) != `{"b":3,"a":2}` {
		t.Fatalf("got %s err=%v", data, err)
	}
	var back Ordered[int]
	if err := json.Unmarshal(data, &back); err != nil || len(back.Keys) != 2 || back.Keys[0] != "b" {
		t.Fatalf("roundtrip failed: %+v err=%v", back, err)
	}
}
