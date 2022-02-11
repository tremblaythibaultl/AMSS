package AMSS

import (
	"crypto/sha256"
)

// Merkle signature scheme parameters

// nbMessages lets this instance of the MSS sign at most nbMessages messages. The height of the tree is lg(nbMessages).
const nbMessages = 1024

// Main tree for the Merkle signature scheme
type merkleSigTree struct {
	hashTree       [2 * nbMessages][n]byte // root at [len-2]
	leaves         [nbMessages]*oneTimeSig
	traversalIndex int
}

func main() {
	newMSS()
}

func newMSS() *merkleSigTree {
	tree := merkleSigTree{}
	treeInit(&tree)
	return &tree
}

// Initializes the new tree with its signature keys and hash-valued nodes
func treeInit(tree *merkleSigTree) {
	for i := 0; i < nbMessages; i++ {
		tree.leaves[i] = newWots()

		var concat []byte
		for j := 0; j < t; j++ {
			concat = append(concat, tree.leaves[i].publicKey[j][:]...)
		}
		tree.hashTree[i] = sha256.Sum256(concat) // hash of the public key of the one-time signature
	}

	// construction of the node hashes
	for i := 0; i < nbMessages; i++ {
		concat := append(tree.hashTree[2*i][:], tree.hashTree[2*i+1][:]...)
		tree.hashTree[nbMessages+i] = sha256.Sum256(concat)
	}
}
