package AMSS

import (
	"crypto/sha256"
	"encoding/binary"
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

func main() {
	sk_init()
	pk_init()
}

/*
Initializes the signature (secret) key with t n-byte random string
*/
func sk_init() {
	rand.Seed(time.Now().UnixNano())
	var rvalue uint64

	for i := 0; i < t; i++ {
		for j := 0; j < n; j += 8 {
			rvalue = rand.Uint64()
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, rvalue)
			for k := 0; k < 8; k++ {
				signature_key[i][j+k] = b[k]
			}
		}
	}
}

func pk_init() {
	for i := 0; i < t; i++ {
		key := signature_key[i]
		for j := 0; j < int(math.Pow(2, w)-1); j++ {
			key = sha256.Sum256(key[:])
		}
		public_key[i] = key
	}
}
