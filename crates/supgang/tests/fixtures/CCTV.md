C2SP CCTV age test vectors, pinned to commit
`b88c4b206254ac543df240097e0f1fcc6a664821` at
https://github.com/C2SP/CCTV/tree/b88c4b206254ac543df240097e0f1fcc6a664821/age/testdata .
The files are byte-for-byte copies of the named test vectors encoded as ASCII hex
because the repository's name guard inspects textual diffs. Decode hex to obtain
the exact original vector bytes. CCTV's age/README.md says its license allows
including copies without attribution; this note records provenance anyway.

The CCTV success vector uses scrypt log2 N=10. A test-only parser range accepts
it to prove wire compatibility. The product parser still refuses values below
18 and above 22. Production encryption writes 20.
