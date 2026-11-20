package crypto

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/cometbft/cometbft/crypto"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	errorsmod "cosmossdk.io/errors"

	"github.com/cosmos/cosmos-sdk/codec/legacy"
	"github.com/cosmos/cosmos-sdk/crypto/keys/bcrypt"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/crypto/xsalsa20symmetric"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const (
	blockTypePrivKey = "TENDERMINT PRIVATE KEY"
	blockTypeKeyInfo = "TENDERMINT KEY INFO"
	blockTypePubKey  = "TENDERMINT PUBLIC KEY"

	defaultAlgo = "secp256k1"

	headerVersion = "version"
	headerType    = "type"
)

var (
	kdfHeader = "kdf"
	kdfBcrypt = "bcrypt"
	kdfArgon2 = "argon2"
)

const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
)

// BcryptSecurityParameter is security parameter var, and it can be changed within the lcd test.
// Making the bcrypt security parameter a var shouldn't be a security issue:
// One can't verify an invalid key by maliciously changing the bcrypt
// parameter during a runtime vulnerability. The main security
// threat this then exposes would be something that changes this during
// runtime before the user creates their key. This vulnerability must
// succeed to update this to that same value before every subsequent call
// to the keys command in future startups / or the attacker must get access
// to the filesystem. However, with a similar threat model (changing
// variables in runtime), one can cause the user to sign a different tx
// than what they see, which is a significantly cheaper attack then breaking
// a bcrypt hash. (Recall that the nonce still exists to break rainbow tables)
// For further notes on security parameter choice, see README.md
var BcryptSecurityParameter uint32 = 12

//-----------------------------------------------------------------
// add armor

// Armor the InfoBytes
func ArmorInfoBytes(bz []byte) string {
	header := map[string]string{
		headerType:    "Info",
		headerVersion: "0.0.0",
	}

	return EncodeArmor(blockTypeKeyInfo, header, bz)
}

// Armor the PubKeyBytes
func ArmorPubKeyBytes(bz []byte, algo string) string {
	header := map[string]string{
		headerVersion: "0.0.1",
	}
	if algo != "" {
		header[headerType] = algo
	}

	return EncodeArmor(blockTypePubKey, header, bz)
}

//-----------------------------------------------------------------
// remove armor

// Unarmor the InfoBytes
func UnarmorInfoBytes(armorStr string) ([]byte, error) {
	bz, header, err := unarmorBytes(armorStr, blockTypeKeyInfo)
	if err != nil {
		return nil, err
	}

	if header[headerVersion] != "0.0.0" {
		return nil, fmt.Errorf("unrecognized version: %v", header[headerVersion])
	}

	return bz, nil
}

// UnarmorPubKeyBytes returns the pubkey byte slice, a string of the algo type, and an error
func UnarmorPubKeyBytes(armorStr string) (bz []byte, algo string, err error) {
	bz, header, err := unarmorBytes(armorStr, blockTypePubKey)
	if err != nil {
		return nil, "", fmt.Errorf("couldn't unarmor bytes: %w", err)
	}

	switch header[headerVersion] {
	case "0.0.0":
		return bz, defaultAlgo, err
	case "0.0.1":
		if header[headerType] == "" {
			header[headerType] = defaultAlgo
		}

		return bz, header[headerType], err
	case "":
		return nil, "", fmt.Errorf("header's version field is empty")
	default:
		err = fmt.Errorf("unrecognized version: %v", header[headerVersion])
		return nil, "", err
	}
}

func unarmorBytes(armorStr, blockType string) (bz []byte, header map[string]string, err error) {
	bType, header, bz, err := DecodeArmor(armorStr)
	if err != nil {
		return
	}

	if bType != blockType {
		err = fmt.Errorf("unrecognized armor type %q, expected: %q", bType, blockType)
		return
	}

	return
}

//-----------------------------------------------------------------
// encrypt/decrypt with armor

// Encrypt and armor the private key.
func EncryptArmorPrivKey(privKey cryptotypes.PrivKey, passphrase, algo string) string {
	saltBytes, encBytes := encryptPrivKey(privKey, passphrase)
	header := map[string]string{
		kdfHeader: kdfArgon2,
		"salt":    fmt.Sprintf("%X", saltBytes),
	}

	if algo != "" {
		header[headerType] = algo
	}

	armorStr := EncodeArmor(blockTypePrivKey, header, encBytes)

	return armorStr
}

func encryptPrivKey(privKey cryptotypes.PrivKey, passphrase string) (saltBytes, encBytes []byte) {
	saltBytes = crypto.CRandBytes(16)

	key := argon2.IDKey([]byte(passphrase), saltBytes, argon2Time, argon2Memory, argon2Threads, chacha20poly1305.KeySize)
	privKeyBytes := legacy.Cdc.MustMarshal(privKey)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(errorsmod.Wrap(err, "error generating cypher from key"))
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(privKeyBytes)+aead.Overhead()) // Nonce is fixed to maintain consistency, each key is generated  at every encryption using a random salt.

	encBytes = aead.Seal(nil, nonce, privKeyBytes, nil)

	return saltBytes, encBytes
}

// UnarmorDecryptPrivKey returns the privkey byte slice, a string of the algo type, and an error
func UnarmorDecryptPrivKey(armorStr, passphrase string) (privKey cryptotypes.PrivKey, algo string, err error) {
	blockType, header, encBytes, err := DecodeArmor(armorStr)
	if err != nil {
		return privKey, "", err
	}

	if blockType != blockTypePrivKey {
		return privKey, "", fmt.Errorf("unrecognized armor type: %v", blockType)
	}

	if header[kdfHeader] != kdfBcrypt && header[kdfHeader] != kdfArgon2 {
		return privKey, "", fmt.Errorf("unrecognized KDF type: %v", header[kdfHeader])
	}

	if header["salt"] == "" {
		return privKey, "", fmt.Errorf("missing salt bytes")
	}

	saltBytes, err := hex.DecodeString(header["salt"])
	if err != nil {
		return privKey, "", fmt.Errorf("error decoding salt: %v", err.Error())
	}

	privKey, err = decryptPrivKey(saltBytes, encBytes, passphrase, header[kdfHeader])

	if header[headerType] == "" {
		header[headerType] = defaultAlgo
	}

	return privKey, header[headerType], err
}

func decryptPrivKey(saltBytes, encBytes []byte, passphrase, kdf string) (privKey cryptotypes.PrivKey, err error) {
	// Key derivation
	var (
		key          []byte
		privKeyBytes []byte
	)

	// Since the argon2 key derivation and chacha encryption was implemented together, it is not possible to have mixed kdf and encryption algorithms
	switch kdf {
	case kdfArgon2:
		key = argon2.IDKey([]byte(passphrase), saltBytes, argon2Time, argon2Memory, argon2Threads, chacha20poly1305.KeySize)

		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return privKey, errorsmod.Wrap(err, "Error generating aead cypher for key.")
		} else if len(encBytes) < aead.NonceSize() {
			return privKey, errorsmod.Wrap(nil, "Encrypted bytes length is smaller than aead nonce size.")
		}
		nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(privKeyBytes)+aead.Overhead())
		privKeyBytes, err = aead.Open(nil, nonce, encBytes, nil) // Decrypt the message and check it wasn't tampered with.
		if err != nil {
			return privKey, sdkerrors.ErrWrongPassword
		}
	case kdfBcrypt:
		key, err = bcrypt.GenerateFromPassword(saltBytes, []byte(passphrase), BcryptSecurityParameter)
		if err != nil {
			return privKey, errorsmod.Wrap(err, "Error generating bcrypt cypher for key.")
		}
		key = crypto.Sha256(key) // Get 32 bytes
		privKeyBytes, err = xsalsa20symmetric.DecryptSymmetric(encBytes, key)

		if errors.Is(err, xsalsa20symmetric.ErrCiphertextDecrypt) {
			return privKey, sdkerrors.ErrWrongPassword
		}
	default:
		return privKey, errorsmod.Wrap(nil, fmt.Sprintf("Unrecognized key derivation function (kdf) header: %s.", kdf))
	}

	if err != nil {
		return privKey, err
	}

	return legacy.PrivKeyFromBytes(privKeyBytes)
}

//-----------------------------------------------------------------
// encode/decode with armor

func EncodeArmor(blockType string, headers map[string]string, data []byte) string {
	buf := new(bytes.Buffer)
	w, err := armorEncode(buf, blockType, headers)
	if err != nil {
		panic(fmt.Errorf("could not encode ascii armor: %w", err))
	}
	_, err = w.Write(data)
	if err != nil {
		panic(fmt.Errorf("could not encode ascii armor: %w", err))
	}
	err = w.Close()
	if err != nil {
		panic(fmt.Errorf("could not encode ascii armor: %w", err))
	}
	return buf.String()
}

func DecodeArmor(armorStr string) (blockType string, headers map[string]string, data []byte, err error) {
	buf := bytes.NewBufferString(armorStr)
	block, err := armorDecode(buf)
	if err != nil {
		return "", nil, nil, err
	}
	data, err = io.ReadAll(block.Body)
	if err != nil {
		return "", nil, nil, err
	}
	return block.Type, block.Header, data, nil
}

//-----------------------------------------------------------------
// OpenPGP ASCII armor codec (RFC 4880, section 6)
//
// The codec below is the armor codec from golang.org/x/crypto/openpgp/armor
// (x/crypto v0.38.0), which the SDK previously imported. That package is
// deprecated and flagged as a whole by GO-2026-5932, and newer x/crypto
// releases no longer contain it. It is reproduced here, unexported, so that
// armored keys keep their exact encoding and every armor the SDK has ever
// accepted still decodes. The only change is that EncodeArmor writes headers
// in sorted key order instead of random map order, which is one of the
// orderings the old encoder could already produce.
//
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at https://go.dev/LICENSE.

// armorError has the type and message of the old
// golang.org/x/crypto/openpgp/errors.StructuralError.
type armorError string

func (e armorError) Error() string {
	return "openpgp: invalid data: " + string(e)
}

// errArmorCorrupt is the old armor.ArmorCorrupt.
var errArmorCorrupt error = armorError("armor invalid")

// armorBlock represents an OpenPGP armored structure.
//
// The encoded form is:
//
//	-----BEGIN Type-----
//	Headers
//
//	base64-encoded Bytes
//	'=' base64 encoded checksum
//	-----END Type-----
//
// where Headers is a possibly empty sequence of Key: Value lines.
type armorBlock struct {
	Type    string            // The type, taken from the preamble (i.e. "TENDERMINT PRIVATE KEY").
	Header  map[string]string // Optional headers.
	Body    io.Reader         // A Reader from which the contents can be read
	lReader armorLineReader
	oReader armorBodyReader
}

const (
	crc24Init = 0xb704ce
	crc24Poly = 0x1864cfb
	crc24Mask = 0xffffff
)

// crc24 calculates the OpenPGP checksum as specified in RFC 4880, section 6.1
func crc24(crc uint32, d []byte) uint32 {
	for _, b := range d {
		crc ^= uint32(b) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= crc24Poly
			}
		}
	}
	return crc
}

var (
	armorStart        = []byte("-----BEGIN ")
	armorEnd          = []byte("-----END ")
	armorEndOfLine    = []byte("-----")
	armorHeaderSep    = []byte(": ")
	armorBlockEnd     = []byte("\n=")
	armorNewline      = []byte("\n")
	armorEndOfLineOut = []byte("-----\n")
)

// armorLineReader wraps a line based reader. It watches for the end of an
// armor block and records the expected CRC value.
type armorLineReader struct {
	in     *bufio.Reader
	buf    []byte
	eof    bool
	crc    uint32
	crcSet bool
}

func (l *armorLineReader) Read(p []byte) (n int, err error) {
	if l.eof {
		return 0, io.EOF
	}

	if len(l.buf) > 0 {
		n = copy(p, l.buf)
		l.buf = l.buf[n:]
		return
	}

	line, isPrefix, err := l.in.ReadLine()
	if err != nil {
		return
	}
	if isPrefix {
		return 0, errArmorCorrupt
	}

	if bytes.HasPrefix(line, armorEnd) {
		l.eof = true
		return 0, io.EOF
	}

	if len(line) == 5 && line[0] == '=' {
		// This is the checksum line
		var expectedBytes [3]byte
		var m int
		m, err = base64.StdEncoding.Decode(expectedBytes[0:], line[1:])
		if m != 3 || err != nil {
			return
		}
		l.crc = uint32(expectedBytes[0])<<16 |
			uint32(expectedBytes[1])<<8 |
			uint32(expectedBytes[2])

		line, _, err = l.in.ReadLine()
		if err != nil && err != io.EOF {
			return
		}
		if !bytes.HasPrefix(line, armorEnd) {
			return 0, errArmorCorrupt
		}

		l.eof = true
		l.crcSet = true
		return 0, io.EOF
	}

	if len(line) > 96 {
		return 0, errArmorCorrupt
	}

	n = copy(p, line)
	bytesToSave := len(line) - n
	if bytesToSave > 0 {
		if cap(l.buf) < bytesToSave {
			l.buf = make([]byte, 0, bytesToSave)
		}
		l.buf = l.buf[0:bytesToSave]
		copy(l.buf, line[n:])
	}

	return
}

// armorBodyReader passes Read calls to the underlying base64 decoder, but
// keeps a running CRC of the resulting data and checks the CRC against the
// value found by the armorLineReader at EOF.
type armorBodyReader struct {
	lReader    *armorLineReader
	b64Reader  io.Reader
	currentCRC uint32
}

func (r *armorBodyReader) Read(p []byte) (n int, err error) {
	n, err = r.b64Reader.Read(p)
	r.currentCRC = crc24(r.currentCRC, p[:n])

	if err == io.EOF && r.lReader.crcSet && r.lReader.crc != r.currentCRC&crc24Mask {
		return 0, errArmorCorrupt
	}

	return
}

// armorDecode reads a PGP armored block from the given Reader. It will ignore
// leading garbage. If it doesn't find a block, it will return nil, io.EOF. The
// given Reader is not usable after calling this function: an arbitrary amount
// of data may have been read past the end of the block.
func armorDecode(in io.Reader) (p *armorBlock, err error) {
	r := bufio.NewReaderSize(in, 100)
	var line []byte
	ignoreNext := false

TryNextBlock:
	p = nil

	// Skip leading garbage
	for {
		ignoreThis := ignoreNext
		line, ignoreNext, err = r.ReadLine()
		if err != nil {
			return
		}
		if ignoreNext || ignoreThis {
			continue
		}
		line = bytes.TrimSpace(line)
		if len(line) > len(armorStart)+len(armorEndOfLine) && bytes.HasPrefix(line, armorStart) {
			break
		}
	}

	p = new(armorBlock)
	p.Type = string(line[len(armorStart) : len(line)-len(armorEndOfLine)])
	p.Header = make(map[string]string)
	nextIsContinuation := false
	var lastKey string

	// Read headers
	for {
		isContinuation := nextIsContinuation
		line, nextIsContinuation, err = r.ReadLine()
		if err != nil {
			p = nil
			return
		}
		if isContinuation {
			p.Header[lastKey] += string(line)
			continue
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			break
		}

		i := bytes.Index(line, armorHeaderSep)
		if i == -1 {
			goto TryNextBlock
		}
		lastKey = string(line[:i])
		p.Header[lastKey] = string(line[i+2:])
	}

	p.lReader.in = r
	p.oReader.currentCRC = crc24Init
	p.oReader.lReader = &p.lReader
	p.oReader.b64Reader = base64.NewDecoder(base64.StdEncoding, &p.lReader)
	p.Body = &p.oReader

	return
}

// armorWriteSlices writes its arguments to the given Writer.
func armorWriteSlices(out io.Writer, slices ...[]byte) (err error) {
	for _, s := range slices {
		_, err = out.Write(s)
		if err != nil {
			return err
		}
	}
	return
}

// armorLineBreaker breaks data across several lines, all of the same byte
// length (except possibly the last). Lines are broken with a single '\n'.
type armorLineBreaker struct {
	lineLength  int
	line        []byte
	used        int
	out         io.Writer
	haveWritten bool
}

func newArmorLineBreaker(out io.Writer, lineLength int) *armorLineBreaker {
	return &armorLineBreaker{
		lineLength: lineLength,
		line:       make([]byte, lineLength),
		used:       0,
		out:        out,
	}
}

func (l *armorLineBreaker) Write(b []byte) (n int, err error) {
	n = len(b)

	if n == 0 {
		return
	}

	if l.used == 0 && l.haveWritten {
		_, err = l.out.Write([]byte{'\n'})
		if err != nil {
			return
		}
	}

	if l.used+len(b) < l.lineLength {
		l.used += copy(l.line[l.used:], b)
		return
	}

	l.haveWritten = true
	_, err = l.out.Write(l.line[0:l.used])
	if err != nil {
		return
	}
	excess := l.lineLength - l.used
	l.used = 0

	_, err = l.out.Write(b[0:excess])
	if err != nil {
		return
	}

	_, err = l.Write(b[excess:])
	return
}

func (l *armorLineBreaker) Close() (err error) {
	if l.used > 0 {
		_, err = l.out.Write(l.line[0:l.used])
		if err != nil {
			return
		}
	}

	return
}

// armorEncoding keeps track of a running CRC24 over the data which has been
// written to it and outputs a OpenPGP checksum when closed, followed by an
// armor trailer.
//
// It's built into a stack of io.Writers:
//
//	armorEncoding -> base64 encoder -> armorLineBreaker -> out
type armorEncoding struct {
	out       io.Writer
	breaker   *armorLineBreaker
	b64       io.WriteCloser
	crc       uint32
	blockType []byte
}

func (e *armorEncoding) Write(data []byte) (n int, err error) {
	e.crc = crc24(e.crc, data)
	return e.b64.Write(data)
}

func (e *armorEncoding) Close() (err error) {
	err = e.b64.Close()
	if err != nil {
		return
	}
	e.breaker.Close()

	var checksumBytes [3]byte
	checksumBytes[0] = byte(e.crc >> 16)
	checksumBytes[1] = byte(e.crc >> 8)
	checksumBytes[2] = byte(e.crc)

	var b64ChecksumBytes [4]byte
	base64.StdEncoding.Encode(b64ChecksumBytes[:], checksumBytes[:])

	return armorWriteSlices(e.out, armorBlockEnd, b64ChecksumBytes[:], armorNewline, armorEnd, e.blockType, armorEndOfLine)
}

// armorEncode returns a WriteCloser which will encode the data written to it
// in OpenPGP armor. Headers are written in sorted key order.
func armorEncode(out io.Writer, blockType string, headers map[string]string) (w io.WriteCloser, err error) {
	bType := []byte(blockType)
	err = armorWriteSlices(out, armorStart, bType, armorEndOfLineOut)
	if err != nil {
		return
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		err = armorWriteSlices(out, []byte(k), armorHeaderSep, []byte(headers[k]), armorNewline)
		if err != nil {
			return
		}
	}

	_, err = out.Write(armorNewline)
	if err != nil {
		return
	}

	e := &armorEncoding{
		out:       out,
		breaker:   newArmorLineBreaker(out, 64),
		crc:       crc24Init,
		blockType: bType,
	}
	e.b64 = base64.NewEncoder(base64.StdEncoding, e.breaker)
	return e, nil
}
