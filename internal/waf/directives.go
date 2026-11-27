package waf

import (
	"fmt"
	"strconv"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

// Modes the handler accepts; Off means no handler at all.
const (
	ModeBlock  = config.FirewallBlock
	ModeDetect = config.FirewallDetect
)

// InspectBytes is how much of a request body the firewall buffers and
// inspects (owner decision of 15 Nov 2026).
const InspectBytes = config.FirewallInspectBytes

// AllowedMethods replaces CRS's default GET HEAD POST OPTIONS, which makes
// rule 911100 block the methods typical JSON APIs use (ADR-0008). Since CRS
// 4.31.0 each entry is wrapped in pipes: rule 911100 compares |METHOD|, so the
// old space-separated list would flag every request.
const AllowedMethods = "|GET| |HEAD| |POST| |OPTIONS| |PUT| |PATCH| |DELETE|"

// directives is the whole Coraza configuration for one mode and paranoia
// level. It is fixed text: no part of it comes from the user's config except
// the two validated enum values.
func directives(mode string, level int) (string, error) {
	var engine, limitAction string
	switch mode {
	case ModeBlock:
		engine, limitAction = "On", "Reject"
	case ModeDetect:
		engine, limitAction = "DetectionOnly", "ProcessPartial"
	default:
		return "", fmt.Errorf("unknown firewall mode %q", mode)
	}
	if level < 1 || level > config.MaxParanoiaLevel {
		return "", fmt.Errorf("paranoia level %d out of range", level)
	}
	limit := strconv.FormatInt(InspectBytes, 10)
	pl := strconv.Itoa(level)
	return `
SecRuleEngine ` + engine + `
SecRequestBodyAccess On
SecRequestBodyLimit ` + limit + `
SecRequestBodyInMemoryLimit ` + limit + `
SecRequestBodyLimitAction ` + limitAction + `
SecRequestBodyJsonDepthLimit 1024
SecArgumentsLimit 1000
SecResponseBodyAccess Off
SecAuditEngine Off

SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" "id:200006,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule URI_PARSE_ERROR "@eq 1" "id:200009,phase:1,t:none,log,deny,status:400,msg:'URI failed to parse.'"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',severity:2"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,t:none,log,deny,status:400,msg:'Multipart request body failed strict validation.'"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:200004,phase:1,t:none,log,deny,status:400,msg:'Argument limit reached.'"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:200005,phase:2,t:none,log,deny,status:400,msg:'Argument limit reached.'"

SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=` + pl + `,setvar:tx.detection_paranoia_level=` + pl + `"
SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=` + AllowedMethods + `'"
SecAction "id:900500,phase:1,pass,t:none,nolog,setvar:tx.crs_skip_response_analysis=1"
SecAction "id:900990,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=` + crsSetupVersion + `"

Include rules/REQUEST-*.conf
`, nil
}
