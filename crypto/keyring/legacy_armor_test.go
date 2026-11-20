package keyring

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// legacyKeyringVector is an export made by the unpatched SDK, whose armor used
// golang.org/x/crypto v0.38.0 openpgp/armor. See crypto/armor_compat_test.go.
type legacyKeyringVector struct {
	Mnemonic   string `json:"mnemonic"`
	Passphrase string `json:"passphrase"`
	Address    string `json:"address"`
	PubKey     string `json:"pubkey"`
	PrivArmor  string `json:"priv_armor"`
	PubArmor   string `json:"pub_armor"`
}

func loadLegacyKeyringVectors(t *testing.T) []legacyKeyringVector {
	t.Helper()
	b, err := os.ReadFile("../testdata/armor_compat_golden.json")
	require.NoError(t, err)
	var g struct {
		Keyring []legacyKeyringVector `json:"keyring"`
	}
	require.NoError(t, json.Unmarshal(b, &g))
	require.NotEmpty(t, g.Keyring)
	return g.Keyring
}

// TestImportLegacyArmoredKeys imports private and public keys exported by the
// unpatched SDK and checks they resolve to the same account, and that a fresh
// public-key export is byte-identical to the legacy export.
func TestImportLegacyArmoredKeys(t *testing.T) {
	cdc := getCodec()
	for _, v := range loadLegacyKeyringVectors(t) {
		t.Run(v.Address, func(t *testing.T) {
			for _, backend := range []string{BackendMemory, BackendTest} {
				kb, err := New("legacyArmor", backend, t.TempDir(), nil, cdc)
				require.NoError(t, err)

				require.NoError(t, kb.ImportPrivKey("priv", v.PrivArmor, v.Passphrase))
				rec, err := kb.Key("priv")
				require.NoError(t, err)
				addr, err := rec.GetAddress()
				require.NoError(t, err)
				require.Equal(t, v.Address, addr.String())
				pk, err := rec.GetPubKey()
				require.NoError(t, err)
				require.Equal(t, v.PubKey, pk.String())

				pubArmor, err := kb.ExportPubKeyArmor("priv")
				require.NoError(t, err)
				require.Equal(t, v.PubArmor, pubArmor)

				kbPub, err := New("legacyArmorPub", backend, t.TempDir(), nil, cdc)
				require.NoError(t, err)
				require.NoError(t, kbPub.ImportPubKey("pub", v.PubArmor))
				pubRec, err := kbPub.Key("pub")
				require.NoError(t, err)
				pubAddr, err := pubRec.GetAddress()
				require.NoError(t, err)
				require.Equal(t, v.Address, pubAddr.String())

				// Wrong passphrase still fails on the legacy armor.
				require.Error(t, kb.ImportPrivKey("wrong", v.PrivArmor, v.Passphrase+"x"))

				// Re-export with the patched codec and import into a new keyring.
				reArmor, err := kb.ExportPrivKeyArmor("priv", "re-export")
				require.NoError(t, err)
				kb2, err := New("legacyArmor2", backend, t.TempDir(), nil, cdc)
				require.NoError(t, err)
				require.NoError(t, kb2.ImportPrivKey("priv", reArmor, "re-export"))
				rec2, err := kb2.Key("priv")
				require.NoError(t, err)
				addr2, err := rec2.GetAddress()
				require.NoError(t, err)
				require.Equal(t, v.Address, addr2.String())
			}
		})
	}
}
