// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tcg

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_DiceExtension_Unmarshal(t *testing.T) {
	data, err := os.ReadFile("test/riot-ext.der")
	assert.Nil(t, err)

	var dice DiceExtension
	rest, err := dice.UnmarshalDER(data)
	assert.Empty(t, rest)
	assert.Nil(t, err)
}

func Test_TCBInfo_flags(t *testing.T) {
	var tv TcbInfo

	tv.Flags = asn1.BitString{
		Bytes:     []byte{0x80},
		BitLength: 8,
	}

	assert.True(t, tv.IsNotConfigured())
	assert.False(t, tv.IsNotSecure())
	assert.False(t, tv.IsRecovery())
	assert.False(t, tv.IsDebug())

	tv.Flags = asn1.BitString{
		Bytes:     []byte{0x40},
		BitLength: 8,
	}

	assert.False(t, tv.IsNotConfigured())
	assert.True(t, tv.IsNotSecure())
	assert.False(t, tv.IsRecovery())
	assert.False(t, tv.IsDebug())

	tv.Flags = asn1.BitString{
		Bytes:     []byte{0x20},
		BitLength: 8,
	}

	assert.False(t, tv.IsNotConfigured())
	assert.False(t, tv.IsNotSecure())
	assert.True(t, tv.IsRecovery())
	assert.False(t, tv.IsDebug())

	tv.Flags = asn1.BitString{
		Bytes:     []byte{0x10},
		BitLength: 8,
	}

	assert.False(t, tv.IsNotConfigured())
	assert.False(t, tv.IsNotSecure())
	assert.False(t, tv.IsRecovery())
	assert.True(t, tv.IsDebug())

	tv.Flags = asn1.BitString{
		Bytes:     []byte{0xf0},
		BitLength: 8,
	}

	assert.True(t, tv.IsNotConfigured())
	assert.True(t, tv.IsNotSecure())
	assert.True(t, tv.IsRecovery())
	assert.True(t, tv.IsDebug())
}

func Test_CrlExtensions_UnmarshalDER(t *testing.T) {
	// Create test CRL extensions data
	crlExt := CrlExtensions{
		CRLDistributionPoints: []CrlDistributionPoint{
			NewCrlDistributionPoint("http://crl.example.com/dice.crl"),
		},
		AuthorityKeyIdentifier: []byte{0x01, 0x02, 0x03, 0x04},
		CRLNumber:             big.NewInt(42),
	}

	// Marshal to DER format
	data, err := asn1.Marshal(crlExt)
	require.NoError(t, err)

	// Unmarshal and verify
	var unmarshaled CrlExtensions
	rest, err := unmarshaled.UnmarshalCrlExtensionsDER(data)
	assert.Empty(t, rest)
	assert.NoError(t, err)
	assert.Len(t, unmarshaled.CRLDistributionPoints, 1)
	assert.Equal(t, "http://crl.example.com/dice.crl", 
		unmarshaled.CRLDistributionPoints[0].DistributionPoint.FullName[0].UniformResourceIdentifier)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, unmarshaled.AuthorityKeyIdentifier)
	assert.Equal(t, int64(42), unmarshaled.CRLNumber.Int64())
}

func Test_DiceCrl_Operations(t *testing.T) {
	crl := &DiceCrl{
		Version:            1,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: []int{1, 2, 840, 113549, 1, 1, 11}}, // SHA256WithRSA
		ThisUpdate:         time.Now(),
		NextUpdate:         time.Now().Add(24 * time.Hour),
	}

	// Test adding revoked certificate
	serialNum := big.NewInt(12345)
	reason := ReasonKeyCompromise
	revocationTime := time.Now()
	
	crl.AddRevokedCertificate(serialNum, revocationTime, &reason)
	
	// Test checking if certificate is revoked
	assert.True(t, crl.IsRevoked(serialNum))
	assert.False(t, crl.IsRevoked(big.NewInt(54321)))
	
	// Test getting revocation reason
	retrievedReason := crl.GetRevocationReason(serialNum)
	require.NotNil(t, retrievedReason)
	assert.Equal(t, ReasonKeyCompromise, *retrievedReason)
	
	// Test non-existent certificate
	assert.Nil(t, crl.GetRevocationReason(big.NewInt(99999)))
}

func Test_CrlDistributionPoint_Creation(t *testing.T) {
	uri := "http://test.example.com/crl/dice.crl"
	dp := NewCrlDistributionPoint(uri)
	
	assert.Len(t, dp.DistributionPoint.FullName, 1)
	assert.Equal(t, uri, dp.DistributionPoint.FullName[0].UniformResourceIdentifier)
}

func Test_RevocationReasonConstants(t *testing.T) {
	// Test that all reason constants are defined with correct values
	assert.Equal(t, 0, ReasonUnspecified)
	assert.Equal(t, 1, ReasonKeyCompromise)
	assert.Equal(t, 2, ReasonCACompromise)
	assert.Equal(t, 3, ReasonAffiliationChanged)
	assert.Equal(t, 4, ReasonSuperseded)
	assert.Equal(t, 5, ReasonCessationOfOperation)
	assert.Equal(t, 6, ReasonCertificateHold)
	assert.Equal(t, 8, ReasonRemoveFromCRL)
	assert.Equal(t, 9, ReasonPrivilegeWithdrawn)
	assert.Equal(t, 10, ReasonAACompromise)
}
