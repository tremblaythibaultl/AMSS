# A Merkle Signature Scheme
A MSS implementation inspired by [[BDS09]](https://doi.org/10.1007/978-3-540-88702-7_3) and [RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391).

Authored by Louis Tremblay Thibault and distributed under the MIT License. 

---
### Potential improvements
- Use [WOTS+](https://eprint.iacr.org/2017/965.pdf) instead of WOTS as a signing primitive
- Use a PRNG for the MSS private key generation
- Use a more efficient MSS tree traversal algorithm
