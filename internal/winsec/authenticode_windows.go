package winsec

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Signature is what a file's embedded Authenticode signature says (S-61).
type Signature struct {
	// Valid: WinVerifyTrust accepted the signature and built its chain to a
	// trusted root.
	Valid bool
	// Subject is the signing certificate's display name, set when Valid.
	Subject string
}

// crypt32 calls that golang.org/x/sys/windows does not wrap, loaded from
// System32 only (convention rule 9).
var (
	modCrypt32           = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = modCrypt32.NewProc("CryptMsgClose")
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
// outbound connections SoiréeHost makes (S-42). A file with no signature, or
// one that does not verify, is reported as not Valid; an error means the
// check itself could not run.
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
		// no signature, a broken one, or an untrusted chain: not Valid
		return Signature{}, nil
	}
	subject, err := signerName(p)
	if err != nil {
		return Signature{}, fmt.Errorf("reading the signer of %s: %w", path, err)
	}
	return Signature{Valid: true, Subject: subject}, nil
}

// signerName returns the display name of the certificate that signed the
// file at p.
func signerName(p *uint16) (string, error) {
	var encoding, contentType, formatType uint32
	var store windows.Handle
	var msg windows.Handle
	err := windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(p), // #nosec G103 -- a UTF-16 path, as the API expects
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_BINARY, 0,
		&encoding, &contentType, &formatType, &store, &msg, nil)
	if err != nil {
		return "", err
	}
	defer windows.CertCloseStore(store, 0)     //nolint:errcheck // nothing to do on failure
	defer procCryptMsgClose.Call(uintptr(msg)) //nolint:errcheck // nothing to do on failure
	var size uint32
	// #nosec G103 -- CryptMsgGetParam fills a caller-sized buffer
	if r, _, err := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		return "", err
	}
	if size < uint32(unsafe.Sizeof(cmsgSignerInfoHead{})) { // #nosec G103 G115 -- the size of a fixed structure
		return "", errors.New("signer information is too short")
	}
	// a slice of uintptr keeps the buffer pointer-aligned
	buf := make([]uintptr, (size+uint32(unsafe.Sizeof(uintptr(0)))-1)/uint32(unsafe.Sizeof(uintptr(0)))) // #nosec G103 G115 -- word size
	// #nosec G103 -- the buffer CryptMsgGetParam fills
	if r, _, err := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return "", err
	}
	si := (*cmsgSignerInfoHead)(unsafe.Pointer(&buf[0])) // #nosec G103 -- CMSG_SIGNER_INFO, filled above
	ci := windows.CertInfo{Issuer: si.Issuer, SerialNumber: si.SerialNumber}
	cert, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
		windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&ci), nil) // #nosec G103 -- the CERT_INFO the find type expects
	if err != nil {
		return "", err
	}
	defer windows.CertFreeCertificateContext(cert) //nolint:errcheck // nothing to do on failure
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0)
	if n <= 1 {
		return "", errors.New("the signing certificate has no name")
	}
	name := make([]uint16, n)
	windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &name[0], n)
	return windows.UTF16ToString(name), nil
}
