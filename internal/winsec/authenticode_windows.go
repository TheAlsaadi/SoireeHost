package winsec

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Signature is what a file's embedded Authenticode signature says (S-61).
type Signature struct {
	// Signed: the file carries an Authenticode signature, valid or not.
	Signed bool
	// Valid: WinVerifyTrust accepted the signature and built its chain to a
	// trusted root.
	Valid bool
	// Subject is the signing certificate's display name, set when Valid.
	Subject string
	// Issuer is the display name of the certificate authority that issued
	// the signing certificate, set when Valid.
	Issuer string
}

// Publisher names who signed: the subject and its issuer, so a
// certificate with the same name from another authority is a different
// publisher (S-61; differential review of 20 Nov 2026).
func (s Signature) Publisher() string {
	if !s.Valid {
		return ""
	}
	return s.Subject + " (issued by " + s.Issuer + ")"
}

// crypt32 calls that golang.org/x/sys/windows does not wrap, loaded from
// System32 only (convention rule 9).
var (
	modCrypt32           = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = modCrypt32.NewProc("CryptMsgClose")
)

// WinVerifyTrust results that mean the file carries no signature at all
// (wintrust.h); x/sys does not name them. Any other failure means a
// signature is there but does not verify.
const (
	trustENoSignature        = 0x800B0100 // TRUST_E_NOSIGNATURE
	trustESubjectFormUnknown = 0x800B0003 // TRUST_E_SUBJECT_FORM_UNKNOWN
)

// cmsgSignerInfoParam is CMSG_SIGNER_INFO_PARAM (wincrypt.h).
const cmsgSignerInfoParam = 6

// cmsgSignerInfoHead is the start of CMSG_SIGNER_INFO: enough to find the
// signer's certificate by issuer and serial number.
type cmsgSignerInfoHead struct {
	Version      uint32
	Issuer       windows.CertNameBlob
	SerialNumber windows.CryptIntegerBlob
}

// FileSignature checks the embedded Authenticode signature of the file open
// as h (found at path). It never goes online: revocation is not checked and
// nothing is fetched, because the update check and the tunnel are the only
// outbound connections SoiréeHost makes (S-42). A file with no signature is
// neither Signed nor Valid; one whose signature does not verify (changed,
// expired, an untrusted or uncached chain) is Signed but not Valid, so a
// caller never mistakes a failed check for an unsigned file (insecure-
// defaults audit of 20 Nov 2026). An error means the check could not run.
func FileSignature(path string, h windows.Handle) (Signature, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Signature{}, err
	}
	fi := windows.WinTrustFileInfo{FilePath: p, File: h}
	fi.Size = uint32(unsafe.Sizeof(fi)) // #nosec G103 G115 -- the size of a fixed Windows structure
	data := windows.WinTrustData{
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fi), // #nosec G103 -- the union member WinTrustData expects for WTD_CHOICE_FILE
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_DISABLE_MD2_MD4,
	}
	data.Size = uint32(unsafe.Sizeof(data)) // #nosec G103 G115 -- the size of a fixed Windows structure
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	if verr != nil {
		var code windows.Errno
		if errors.As(verr, &code) && (uint32(code) == trustENoSignature || uint32(code) == trustESubjectFormUnknown) {
			return Signature{}, nil
		}
		// a signature that does not verify: a changed file, a broken or
		// expired signature, or a chain not trusted here
		return Signature{Signed: true}, nil
	}
	subject, issuer, err := signerName(p)
	if err != nil {
		return Signature{}, fmt.Errorf("reading the signer of %s: %w", path, err)
	}
	return Signature{Signed: true, Valid: true, Subject: subject, Issuer: issuer}, nil
}

// signerName returns the display names of the certificate that signed the
// file at p and of its issuer.
func signerName(p *uint16) (subject, issuer string, err error) {
	var encoding, contentType, formatType uint32
	var store windows.Handle
	var msg windows.Handle
	err = windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(p), // #nosec G103 -- a UTF-16 path, as the API expects
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_BINARY, 0,
		&encoding, &contentType, &formatType, &store, &msg, nil)
	if err != nil {
		return "", "", err
	}
	defer windows.CertCloseStore(store, 0)     //nolint:errcheck // nothing to do on failure
	defer procCryptMsgClose.Call(uintptr(msg)) //nolint:errcheck // nothing to do on failure
	var size uint32
	// #nosec G103 -- CryptMsgGetParam fills a caller-sized buffer
	if r, _, err := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		return "", "", err
	}
	if size < uint32(unsafe.Sizeof(cmsgSignerInfoHead{})) { // #nosec G103 G115 -- the size of a fixed structure
		return "", "", errors.New("signer information is too short")
	}
	// a slice of uintptr keeps the buffer pointer-aligned
	buf := make([]uintptr, (size+uint32(unsafe.Sizeof(uintptr(0)))-1)/uint32(unsafe.Sizeof(uintptr(0)))) // #nosec G103 G115 -- word size
	// #nosec G103 -- the buffer CryptMsgGetParam fills
	if r, _, err := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return "", "", err
	}
	si := (*cmsgSignerInfoHead)(unsafe.Pointer(&buf[0])) // #nosec G103 -- CMSG_SIGNER_INFO, filled above
	ci := windows.CertInfo{Issuer: si.Issuer, SerialNumber: si.SerialNumber}
	cert, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
		windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&ci), nil) // #nosec G103 -- the CERT_INFO the find type expects
	if err != nil {
		return "", "", err
	}
	defer windows.CertFreeCertificateContext(cert) //nolint:errcheck // nothing to do on failure
	if subject = certName(cert, 0); subject == "" {
		return "", "", errors.New("the signing certificate has no name")
	}
	if issuer = certName(cert, windows.CERT_NAME_ISSUER_FLAG); issuer == "" {
		return "", "", errors.New("the signing certificate's issuer has no name")
	}
	return subject, issuer, nil
}

// certName is the simple display name of cert, or of its issuer with
// CERT_NAME_ISSUER_FLAG; "" if it has none.
func certName(cert *windows.CertContext, flags uint32) string {
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nil, nil, 0)
	if n <= 1 {
		return ""
	}
	name := make([]uint16, n)
	windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nil, &name[0], n)
	return windows.UTF16ToString(name)
}
