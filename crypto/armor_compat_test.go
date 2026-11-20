package crypto_test

import (
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/crypto"
)

// armorGoldenPath holds vectors produced by the unpatched SDK, whose
// EncodeArmor/DecodeArmor used golang.org/x/crypto v0.38.0 openpgp/armor.
// The in-tree codec must reproduce them exactly.
const armorGoldenPath = "testdata/armor_compat_golden.json"

type armorGoldenEncode struct {
	BlockType string            `json:"block_type"`
	Headers   map[string]string `json:"headers"`
	Data      []byte            `json:"data"`
	Armor     string            `json:"armor"`
}

type armorGoldenDecode struct {
	Input   string            `json:"input"`
	Type    string            `json:"type"`
	Headers map[string]string `json:"headers"`
	Data    []byte            `json:"data"`
	Err     string            `json:"err"`
}

type armorGolden struct {
	Generator string              `json:"generator"`
	Encode    []armorGoldenEncode `json:"encode"`
	Decode    []armorGoldenDecode `json:"decode"`
}

func loadArmorGolden(t *testing.T) armorGolden {
	t.Helper()
	b, err := os.ReadFile(armorGoldenPath)
	require.NoError(t, err)
	var g armorGolden
	require.NoError(t, json.Unmarshal(b, &g))
	require.NotEmpty(t, g.Encode)
	require.NotEmpty(t, g.Decode)
	return g
}

// TestEncodeArmorMatchesLegacyEncoder checks that EncodeArmor output is
// byte-identical to output of the old x/crypto encoder. The golden vectors
// keep only old outputs whose headers happened to come out in sorted order;
// the old encoder cannot produce that order for every multi-header input, but
// it does for the header sets the SDK writes, and header order does not affect
// decoding.
func TestEncodeArmorMatchesLegacyEncoder(t *testing.T) {
	g := loadArmorGolden(t)
	for i, c := range g.Encode {
		require.Equal(t, c.Armor, crypto.EncodeArmor(c.BlockType, c.Headers, c.Data), "encode vector %d", i)
	}
}

// TestDecodeArmorMatchesLegacyDecoder replays valid, hand-crafted malformed
// and randomly mutated armor through DecodeArmor and requires the same block
// type, headers, data and error as the old x/crypto decoder returned.
func TestDecodeArmorMatchesLegacyDecoder(t *testing.T) {
	g := loadArmorGolden(t)
	var accepted, rejected int
	for i, c := range g.Decode {
		bt, hs, data, err := crypto.DecodeArmor(c.Input)
		if c.Err != "" {
			require.EqualError(t, err, c.Err, "decode vector %d: %q", i, c.Input)
			rejected++
		} else {
			require.NoError(t, err, "decode vector %d: %q", i, c.Input)
			accepted++
		}
		require.Equal(t, c.Type, bt, "decode vector %d", i)
		require.Equal(t, c.Headers, hs, "decode vector %d", i)
		require.Equal(t, c.Data, data, "decode vector %d", i)
	}
	// The corpus must exercise both outcomes, or it proves little.
	require.Greater(t, accepted, 100)
	require.Greater(t, rejected, 100)
}

// TestDecodeArmorLegacyEncodeOutput decodes every armor the old encoder
// produced and requires the original payload and headers back.
func TestDecodeArmorLegacyEncodeOutput(t *testing.T) {
	g := loadArmorGolden(t)
	for i, c := range g.Encode {
		bt, hs, data, err := crypto.DecodeArmor(c.Armor)
		require.NoError(t, err, "encode vector %d", i)
		require.Equal(t, c.BlockType, bt)
		want := c.Headers
		if want == nil {
			want = map[string]string{}
		}
		require.Equal(t, want, hs)
		require.Equal(t, len(c.Data), len(data))
		require.Equal(t, c.Data, data)
	}
}

func TestArmorRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 500; i++ {
		data := make([]byte, rng.Intn(3000))
		rng.Read(data)
		// Non-empty keys and values: the legacy decoder trims a header line,
		// so "key: " with an empty value is not a valid header there either.
		headers := map[string]string{}
		for j := rng.Intn(5); j > 0; j-- {
			headers[strings.Repeat(string(rune('a'+rng.Intn(26))), 1+rng.Intn(8))] = strings.Repeat("V", 1+rng.Intn(40))
		}
		armored := crypto.EncodeArmor("TENDERMINT PRIVATE KEY", headers, data)
		require.Equal(t, armored, crypto.EncodeArmor("TENDERMINT PRIVATE KEY", headers, data), "encoding must be deterministic")
		bt, hs, got, err := crypto.DecodeArmor(armored)
		require.NoError(t, err)
		require.Equal(t, "TENDERMINT PRIVATE KEY", bt)
		require.Equal(t, headers, hs)
		require.Equal(t, data, got)
	}
}

func TestDecodeArmorRejectsBadChecksum(t *testing.T) {
	armored := crypto.EncodeArmor("TENDERMINT PUBLIC KEY", map[string]string{"version": "0.0.1"}, []byte("payload"))
	i := strings.LastIndex(armored, "\n=")
	require.Positive(t, i)
	sum := []byte(armored[i+2 : i+6])
	if sum[0] == 'A' {
		sum[0] = 'B'
	} else {
		sum[0] = 'A'
	}
	_, _, _, err := crypto.DecodeArmor(armored[:i+2] + string(sum) + armored[i+6:])
	require.EqualError(t, err, "openpgp: invalid data: armor invalid")
}

func FuzzDecodeArmor(f *testing.F) {
	f.Add(crypto.EncodeArmor("TENDERMINT PUBLIC KEY", map[string]string{"version": "0.0.1", "type": "secp256k1"}, []byte("seed")))
	f.Add("-----BEGIN X-----\n\nQUJD\n=AAAA\n-----END X-----")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		bt, hs, data, err := crypto.DecodeArmor(in)
		if err != nil {
			return
		}
		// Anything accepted re-encodes to armor that decodes to the same values.
		bt2, hs2, data2, err := crypto.DecodeArmor(crypto.EncodeArmor(bt, hs, data))
		if strings.ContainsAny(bt, "\r\n") || strings.Contains(bt, "-----") {
			return
		}
		for k, v := range hs {
			if k == "" || strings.ContainsAny(k+v, "\r\n") || strings.Contains(k, ": ") || strings.TrimSpace(k) != k || strings.TrimSpace(v) != v || len(k)+len(v)+2 >= 100 {
				return
			}
		}
		require.NoError(t, err)
		require.Equal(t, bt, bt2)
		require.Equal(t, hs, hs2)
		require.Equal(t, data, data2)
	})
}
