package AMSS

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"time"
)

/**
Winternitz one-time signature scheme parameters
*/
const n = 32 // Size (in bytes) of the message to sign
const w = 16 // Winternitz parameter
const t = 18 // computed in function of n and w
var signature_key [t][n]byte
var public_key [t][n]byte
var signature [t][n]byte

func main() {
	sk_init()
	pk_init()
	sign(sha256.Sum256([]byte("gm!")))
	verify(sha256.Sum256([]byte("gm!")), signature)
}

// Initializes the OTS secret (signature) key with t n-byte random strings
func sk_init() {
	rand.Seed(time.Now().UnixNano())
	var rvalue uint64

	for i := 0; i < t; i++ {
		for j := 0; j < n; j += 8 {
			rvalue = rand.Uint64()
			b := make([]byte, 8)
			binary.BigEndian.PutUint64(b, rvalue)
			for k := 0; k < 8; k++ {
				signature_key[i][j+k] = b[k]
			}
		}
	}
}

// Initializes the OTS public key from the signature key
func pk_init() {
	for i := 0; i < t; i++ {
		key := signature_key[i]
		for j := 0; j < int(math.Pow(2, w)-1); j++ {
			key = sha256.Sum256(key[:])
		}
		public_key[i] = key
	}
}

func compute_bit_strings(digest [32]byte) [t]uint16 {
	var bit_strings [t]uint16
	var checksum uint32 = 0
	t1 := math.Ceil(n * 8 / w)

	// compute checksum of each of the t1 strings of length w,
	// and fill the bit_strings array with all the 16-bit chunks of the digest.
	for i := 0; i < int(t1); i++ {
		bit_strings[i] = binary.BigEndian.Uint16(digest[2*i : 2*(i+1)])
		checksum += uint32(math.Pow(2, w)) - uint32(bit_strings[i])
	}

	// t2 := int(math.Ceil((math.Floor(math.Log2(t1)) + 1 + w) / w))
	// computing the last t2 w-bit strings
	bit_strings[16] = uint16(checksum >> 16)
	bit_strings[17] = uint16(checksum)

	return bit_strings
}

// Signs a message digest of 256 bits
func sign(digest [32]byte) {
	var bit_strings = compute_bit_strings(digest)

	//fmt.Println(checksum)

	for i := 0; i < t; i++ {
		sig := signature_key[i]
		for j := uint16(0); j < bit_strings[i]; j++ {
			sig = sha256.Sum256(sig[:])
		}
		signature[i] = sig
	}
}

func verify(digest [32]byte, sig [t][n]byte) {
	var bit_strings = compute_bit_strings(digest)

	for i := 0; i < t; i++ {
		verif := sig[i]
		for j := uint32(0); j < uint32(math.Pow(2, w))-1-uint32(bit_strings[i]); j++ {
			verif = sha256.Sum256(verif[:])
		}
		for j := 0; j < len(verif); j++ {
			if verif[j] != public_key[i][j] {
				fmt.Println("Invalid signature")
				// TODO : handle invalid signatures
			}
		}
	}
}
