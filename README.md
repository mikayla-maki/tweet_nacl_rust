NOT SECURE. DO NOT USE.

A rust implementation of x25519 based on Martin's paper, adapted for Rust:

https://martin.kleppmann.com/papers/curve25519.pdf

Each listing is marked with a '//Listing _', where _ is the listing number according to the paper.
I am unsure if the memory access guarantees still hold in my implementation as the borrow checker 
complains about my naive implementation of the output pattern used here (e.g. fmul(&mut c,c,c))