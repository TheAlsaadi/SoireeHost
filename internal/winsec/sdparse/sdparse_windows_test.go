package sdparse

import "testing"

// SE-04: one reading of an SDDL descriptor for every applier. A present,
// non-NULL, protected DACL is required; an owner is optional; a group or a
// SACL, which no applier writes, is refused.
func TestParse(t *testing.T) {
	cases := []struct {
		name, sddl string
		ok, owner  bool
	}{
		{"protected DACL", "D:P(A;OICI;FA;;;SY)", true, false},
		{"owner and protected DACL", "O:BAD:P(A;OICI;FA;;;SY)", true, true},
		{"protected and auto-inherited", "D:PAI(A;OICI;FA;;;SY)", true, false},
		{"empty protected DACL", "D:P", true, false},
		{"no DACL", "O:BA", false, false},
		{"NULL DACL", "D:NO_ACCESS_CONTROL", false, false},
		{"protected NULL DACL", "D:PNO_ACCESS_CONTROL", false, false},
		{"missing P", "D:(A;OICI;FA;;;SY)", false, false},
		{"auto-inherited without P", "O:BAD:AI(A;OICI;FA;;;SY)", false, false},
		{"group", "O:BAG:BAD:P(A;OICI;FA;;;SY)", false, false},
		{"SACL", "D:P(A;OICI;FA;;;SY)S:(AU;SA;FA;;;WD)", false, false},
		{"mandatory label", "D:P(A;OICI;FA;;;SY)S:(ML;;NW;;;LW)", false, false},
		{"not SDDL", "D:P(A;;nonsense", false, false},
		{"empty", "", false, false},
	}
	for _, c := range cases {
		d, err := Parse(c.sddl)
		if (err == nil) != c.ok {
			t.Errorf("%s (%q): err = %v, want ok = %v", c.name, c.sddl, err, c.ok)
			continue
		}
		if err != nil {
			continue
		}
		if d.SD == nil || d.DACL == nil {
			t.Errorf("%s: descriptor or DACL missing from the result", c.name)
		}
		if (d.Owner != nil) != c.owner {
			t.Errorf("%s: owner = %v, want one: %v", c.name, d.Owner, c.owner)
		}
	}
}

// FuzzParse: whatever Parse accepts has a present, non-NULL, protected DACL.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"D:P(A;OICI;FA;;;SY)", "O:BAD:P", "D:NO_ACCESS_CONTROL", "D:(A;;FA;;;WD)", "O:BAG:BAD:P"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sddl string) {
		d, err := Parse(sddl)
		if err != nil {
			return
		}
		if d.DACL == nil {
			t.Fatalf("%q: accepted without a DACL", sddl)
		}
		control, _, err := d.SD.Control()
		if err != nil || control&0x1000 == 0 { // SE_DACL_PROTECTED
			t.Fatalf("%q: accepted an unprotected DACL", sddl)
		}
	})
}
