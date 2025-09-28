// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tcg

// This package implements the DICE attestation structure as defined by
//    https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// DiceOID is the standard object identifier for the DICE extension
var DiceOID = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1}

// DiceTcbInfoOid encodes the TCBInfo extension OID
var DiceTcbInfoOid = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 2}

// CrlExtensionsOid encodes the CRL Extensions OID as defined in Section 6.2
var CrlExtensionsOid = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 3}

// Revocation reason codes as defined in RFC 5280
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonCACompromise         = 2
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
	ReasonCertificateHold      = 6
	// 7 is not used
	ReasonRemoveFromCRL        = 8
	ReasonPrivilegeWithdrawn   = 9
	ReasonAACompromise         = 10
)

type FwID struct {
	// HashAlg is an algorithm identifier for the hash algorithm used to
	// produce the Digest value.
	HashAlg asn1.ObjectIdentifier
	// Digest is a digest of firmware, initialization values or other
	// settings of the target TCB.
	Digest []byte
}

type TcbInfo struct {
	// Vender is the entity that created the target TCB (e.g., a TCI
	// value).
	Vendor string `asn1:"tag:0,implicit,optional,utf8"`
	// Model is the product name associated with the target TCB.
	Model string `asn1:"tag:1,implicit,optional,utf8"`
	// Version is the revision string associated with the target TCB.
	Version string `asn1:"tag:2,implicit,optional,utf8"`
	// Svn is the security version number associated with the target TCB.
	Svn int `asn1:"tag:3,implicit,optional"`
	// Layer is the DICE layer associated with the target TCB.
	Layer int `asn1:"tag:4,implicit,optional"`
	// Index enumerates assests or keys within the target TCB and DICE
	// layer.
	Index int `asn1:"tag:5,implicit,optional"`
	// FwIDList is a list of FWID valuees resulting from applying the
	// HashAlg function over the target TCB values used to compute TCI and
	// CDI values. It is computed by the DICE layer that is the Attesting
	// Environment and certificate Issues.
	FwIDList []FwID `asn1:"tag:6,implicit,optional,omitempty"`
	// Flags enumerates possible TCB states. A TCB MAY operate according to
	// combinations of these operational states (in bit order, starting
	// with bit 0): notConfigured, notSecure, recover, debug.
	Flags asn1.BitString `asn1:"tag:7,implicit,optional"`
	// VendorInfo contains vendor-supplied values that encode vendor-,
	// model-, or device-specific state.
	VendorInfo []byte `asn1:"tag:8,implicit,optional,omitempty"`
}

func (o TcbInfo) IsNotConfigured() bool {
	return o.Flags.At(0) == 1
}

func (o TcbInfo) IsNotSecure() bool {
	return o.Flags.At(1) == 1
}

func (o TcbInfo) IsRecovery() bool {
	return o.Flags.At(2) == 1
}

func (o TcbInfo) IsDebug() bool {
	return o.Flags.At(3) == 1
}

// CrlDistributionPoint represents a CRL distribution point as defined in RFC 5280
type CrlDistributionPoint struct {
	// DistributionPoint contains the name of the distribution point
	DistributionPoint DistributionPointName `asn1:"tag:0,implicit,optional"`
	// Reasons specifies the reason codes for which the CRL should be consulted
	Reasons asn1.BitString `asn1:"tag:1,implicit,optional"`
	// CRLIssuer identifies the issuer of the CRL
	CRLIssuer []GeneralName `asn1:"tag:2,implicit,optional"`
}

// DistributionPointName represents the name of a distribution point
type DistributionPointName struct {
	// FullName contains the full name of the distribution point
	FullName []GeneralName `asn1:"tag:0,implicit,optional"`
	// NameRelativeToCRLIssuer contains the name relative to the CRL issuer
	NameRelativeToCRLIssuer pkix.RDNSequence `asn1:"tag:1,implicit,optional"`
}

// GeneralName represents a general name as defined in RFC 5280
type GeneralName struct {
	OtherName                 []byte        `asn1:"tag:0,implicit,optional"`
	RFC822Name                string        `asn1:"tag:1,implicit,optional"`
	DNSName                   string        `asn1:"tag:2,implicit,optional"`
	X400Address               []byte        `asn1:"tag:3,implicit,optional"`
	DirectoryName             pkix.Name     `asn1:"tag:4,explicit,optional"`
	EDIPartyName              []byte        `asn1:"tag:5,implicit,optional"`
	UniformResourceIdentifier string        `asn1:"tag:6,implicit,optional"`
	IPAddress                 []byte        `asn1:"tag:7,implicit,optional"`
	RegisteredID              asn1.ObjectIdentifier `asn1:"tag:8,implicit,optional"`
}

// CrlEntry represents an entry in a Certificate Revocation List
type CrlEntry struct {
	// SerialNumber of the revoked certificate
	SerialNumber *big.Int
	// RevocationTime when the certificate was revoked
	RevocationTime time.Time
	// Reason for revocation (optional)
	Reason *int `asn1:"tag:0,explicit,optional"`
	// Extensions for this CRL entry (optional)
	Extensions []pkix.Extension `asn1:"optional"`
}

// DiceCrl represents a DICE-specific Certificate Revocation List
type DiceCrl struct {
	// Version of the CRL (v1 = 0, v2 = 1)
	Version int `asn1:"optional,default:0"`
	// SignatureAlgorithm identifies the algorithm used to sign the CRL
	SignatureAlgorithm pkix.AlgorithmIdentifier
	// Issuer of the CRL
	Issuer pkix.Name
	// ThisUpdate indicates when this CRL was issued
	ThisUpdate time.Time
	// NextUpdate indicates when the next CRL will be issued
	NextUpdate time.Time `asn1:"optional"`
	// RevokedCertificates contains the list of revoked certificates
	RevokedCertificates []CrlEntry `asn1:"optional"`
	// Extensions for this CRL (v2 only)
	Extensions []pkix.Extension `asn1:"tag:0,explicit,optional"`
}

// CrlExtensions represents DICE-specific CRL extensions as defined in Section 6.2
type CrlExtensions struct {
	// CRLDistributionPoints extension as defined in RFC 5280
	CRLDistributionPoints []CrlDistributionPoint `asn1:"tag:0,implicit,optional"`
	// AuthorityKeyIdentifier identifies the key used to sign the CRL
	AuthorityKeyIdentifier []byte `asn1:"tag:1,implicit,optional"`
	// CRLNumber provides a sequence number for the CRL
	CRLNumber *big.Int `asn1:"tag:2,implicit,optional"`
	// DeltaCRLIndicator indicates this is a delta CRL
	DeltaCRLIndicator *big.Int `asn1:"tag:3,implicit,optional"`
	// IssuingDistributionPoint identifies the scope of the CRL
	IssuingDistributionPoint *CrlDistributionPoint `asn1:"tag:4,implicit,optional"`
}

// This structure is defined in pkix package but is not exported, so
// re-definding here.
type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// FirmwareID contains the digest that is result of applying the specified
// hash algorithm over the object being measured.
type FirmwareID struct {
	HashAlg asn1.ObjectIdentifier
	Fwid    []byte
}

// CompositeDeviceID combines the firmware id with
type CompositeDeviceID struct {
	Version  int
	DeviceID SubjectPublicKeyInfo
	Fwid     FirmwareID
}

// DiceData is the attestation data encapsulated in the DiceExtension
// nolint: golint
type DiceData struct {
	Oid               asn1.ObjectIdentifier
	CompositeDeviceID CompositeDeviceID
}

// DiceExtension is the x509 v3 extension for DICE attestation.
// nolint: golint
type DiceExtension struct {
	DiceData `asn1:"tag:0,implicit,optional"`
}

// UnmarshalDER populates the DiceExtension from the provided DER-encoded data
// extracted from the certificate extension.
func (re *DiceExtension) UnmarshalDER(data []byte) ([]byte, error) {
	rest, err := asn1.Unmarshal(data, re)

	if err == nil && !re.Oid.Equal(DiceOID) {
		err = errors.New("decoded value does not have the Dice Exteision OID")
	}

	return rest, err
}

// UnmarshalCrlExtensionsDER populates the CrlExtensions from the provided DER-encoded data
// extracted from the CRL extension.
func (crl *CrlExtensions) UnmarshalCrlExtensionsDER(data []byte) ([]byte, error) {
	rest, err := asn1.Unmarshal(data, crl)
	return rest, err
}

// NewCrlDistributionPoint creates a new CRL distribution point with the specified URI
func NewCrlDistributionPoint(uri string) CrlDistributionPoint {
	return CrlDistributionPoint{
		DistributionPoint: DistributionPointName{
			FullName: []GeneralName{
				{UniformResourceIdentifier: uri},
			},
		},
	}
}

// IsRevoked checks if a certificate serial number is present in the revoked certificates list
func (crl *DiceCrl) IsRevoked(serialNumber *big.Int) bool {
	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber.Cmp(serialNumber) == 0 {
			return true
		}
	}
	return false
}

// GetRevocationReason returns the revocation reason for a certificate if it's revoked
func (crl *DiceCrl) GetRevocationReason(serialNumber *big.Int) *int {
	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber.Cmp(serialNumber) == 0 {
			return entry.Reason
		}
	}
	return nil
}

// AddRevokedCertificate adds a certificate to the revoked list
func (crl *DiceCrl) AddRevokedCertificate(serialNumber *big.Int, revocationTime time.Time, reason *int) {
	entry := CrlEntry{
		SerialNumber:   serialNumber,
		RevocationTime: revocationTime,
		Reason:        reason,
	}
	crl.RevokedCertificates = append(crl.RevokedCertificates, entry)
}
