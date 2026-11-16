package rules

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func example(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../configs/rules/et-vnc-scan.rules")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLoadETRule(t *testing.T) {
	rules, err := Load(strings.NewReader(example(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	r := rules[0]
	if r.SID != 2002910 || r.Revision != 6 || r.Message != "ET SCAN Potential VNC Scan 5800-5820" {
		t.Fatalf("identity = %+v", r)
	}
	if r.Source.Network != "$EXTERNAL_NET" || r.Destination.Network != "$HOME_NET" || r.Source.Ports != (PortRange{0, 65535}) || r.Destination.Ports != (PortRange{5800, 5820}) {
		t.Fatalf("header = %+v -> %+v", r.Source, r.Destination)
	}
	if r.Flags != "S,12" || !r.ToServer || r.Class != "attempted-recon" || r.Threshold != (Threshold{Type: "both", Track: "by_src", Count: 5, Seconds: 60}) || r.Metadata == "" {
		t.Fatalf("options = %+v", r)
	}
}

func TestLoadRejectsUnsupportedOrInvalidRules(t *testing.T) {
	original := example(t)
	tests := []struct{ name, old, new string }{
		{"unknown_keyword", "flow:to_server;", "content:\"GET\";"},
		{"flow_state", "flow:to_server;", "flow:established,to_server;"},
		{"action", "alert tcp", "drop tcp"},
		{"protocol", "alert tcp", "alert udp"},
		{"direction", " -> ", " <> "},
		{"network_list", "$HOME_NET", "[192.0.2.1,192.0.2.2]"},
		{"unknown_variable", "$HOME_NET", "$HTTP_SERVERS"},
		{"reverse_range", "5800:5820", "5820:5800"},
		{"large_port", "5800:5820", "65536"},
		{"fractional_port", "5800:5820", "1.2"},
		{"bad_flags", "flags:S,12;", "flags:S+;"},
		{"threshold_type", "type both", "type limit"},
		{"threshold_track", "track by_src", "track by_dst"},
		{"missing_count", "count 5, ", ""},
		{"duplicate_count", "count 5", "count 5, count 8"},
		{"zero_count", "count 5", "count 0"},
		{"zero_seconds", "seconds 60", "seconds 0"},
		{"negative_sid", "sid:2002910", "sid:-1"},
		{"overflow_sid", "sid:2002910", "sid:4294967296"},
		{"missing_revision", "rev:6;", ""},
		{"duplicate_sid", "sid:2002910;", "sid:2002910; sid:1;"},
		{"missing_semicolon", "rev:6;", "rev:6"},
		{"missing_message", "msg:\"ET SCAN Potential VNC Scan 5800-5820\";", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Replace(original, tt.old, tt.new, 1)
			if input == original {
				t.Fatal("test mutation did not change input")
			}
			got, err := Load(strings.NewReader(input))
			if err == nil || got != nil {
				t.Fatalf("rules = %+v, error = %v; want atomic rejection", got, err)
			}
			if !strings.Contains(err.Error(), "строка") {
				t.Fatalf("missing line number: %v", err)
			}
		})
	}
}

func TestLoadQuotedMessage(t *testing.T) {
	input := strings.Replace(example(t), `msg:"ET SCAN Potential VNC Scan 5800-5820"`, `msg:"test; colon: quote \" slash \\"`, 1)
	got, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Message != `test; colon: quote " slash \` {
		t.Fatalf("message = %q", got[0].Message)
	}
}

func TestLoadFileErrors(t *testing.T) {
	original := example(t)
	tests := []struct{ name, input string }{
		{"empty", ""}, {"comments_only", "# disabled\n"},
		{"duplicate_rules", original + "\n" + original},
		{"invalid_after_valid", original + "\ninvalid rule"},
		{"too_large", strings.Repeat("#", maxFileSize+1)},
		{"long_line", strings.Repeat("#", maxLineSize+1)},
		{"unterminated_quote", `alert tcp any any -> any any (msg:"unfinished;)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(strings.NewReader(tt.input))
			if err == nil || got != nil {
				t.Fatalf("rules = %+v, error = %v", got, err)
			}
		})
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestLoadReadError(t *testing.T) {
	_, err := Load(brokenReader{})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v", err)
	}
}

func FuzzLoad(f *testing.F) {
	f.Add(`alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"scan"; flow:to_server; flags:S,12; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-recon; sid:2002910; rev:6;)`)
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) { _, _ = Load(strings.NewReader(input)) })
}
