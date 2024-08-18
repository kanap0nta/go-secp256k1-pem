package s256_pem

import (
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestNewPemPair(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "successful case",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := NewPemPair()
			if (err != nil) != tt.wantErr {
				t.Errorf("NewPemPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) == 0 || len(got1) == 0 {
				t.Errorf("NewPemPair() produced empty keys")
			}
		})
	}
}

func TestPrivateKeyToPem(t *testing.T) {
	priv, _ := secp256k1.GeneratePrivateKey()
	tests := []struct {
		name    string
		args    *secp256k1.PrivateKey
		wantErr bool
	}{
		{
			name:    "successful case",
			args:    priv,
			wantErr: false,
		},
		{
			name:    "nil private key",
			args:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PrivateKeyToPem(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivateKeyToPem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == false && len(got) == 0 {
				t.Errorf("PrivateKeyToPem() produced empty PEM data")
			}
		})
	}
}

func TestPemToPrivateKey(t *testing.T) {
	priv, _ := secp256k1.GeneratePrivateKey()
	privPem, _ := PrivateKeyToPem(priv)

	invalidPem := []byte("invalid")
	corruptedPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{0x00}})

	tests := []struct {
		name    string
		args    []byte
		want    *secp256k1.PrivateKey
		wantErr bool
	}{
		{
			name:    "successful case",
			args:    privPem,
			want:    priv,
			wantErr: false,
		},
		{
			name:    "invalid PEM format",
			args:    invalidPem,
			wantErr: true,
		},
		{
			name:    "corrupted PEM data",
			args:    corruptedPem,
			wantErr: true,
		},
		{
			name:    "invalid ASN.1 data",
			args:    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{0x01}}), // Incorrect ASN.1 data
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PemToPrivateKey(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("PemToPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PemToPrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicKeyToPem(t *testing.T) {
	priv, _ := secp256k1.GeneratePrivateKey()
	pub := priv.PubKey()
	tests := []struct {
		name    string
		args    *secp256k1.PublicKey
		wantErr bool
	}{
		{
			name:    "successful case",
			args:    pub,
			wantErr: false,
		},
		{
			name:    "nil public key",
			args:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PublicKeyToPem(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKeyToPem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == false && len(got) == 0 {
				t.Errorf("PublicKeyToPem() produced empty PEM data")
			}
		})
	}
}
