use rand::Rng;

//listing 1
//This cryptography use 255 bit numbers, too large to fit in standard types integer types.
//therefore, We use 32 element byte arrays as input and output of our code.
type U8_32 = [u8; 32]; //Little endian array order
                       //Internally, it's easier to use an array of 16 elements, with 2 bytes in each elements.
                       //We use i64 so that math simply overflows without loss due to wrapping and we can manage
                       //carrying the bits forward ourselves
type FieldElem = [i64; 16]; //Little endian array order

//Turns a compact, external value into our internal, FieldElem format.
fn unpack25519(input: U8_32) -> FieldElem {
    let mut out: FieldElem = [0; 16];

    for i in 0..16 {
        out[i] = input[2 * i] as i64 + ((input[2 * i + 1] as i64) << 8);
    }

    out
}

//Because we're using an array of i64s, bits outside of the first 16 can be set after the other operations.
// This function carries those bits forward and recalculates each element in the array. 3 calls to this function
// are sufficient to guarantee that all values are within [0, 2^16 - 1]
fn carry25519(elem: &mut FieldElem) {
    let mut carry: i64;
    for i in 0..16 {
        carry = elem[i] >> 16;
        elem[i] -= carry << 16;
        if i < 15 {
            elem[i + 1] += carry;
        } else {
            elem[0] += 38 * carry;
        }
    }
}

//Helper function for adding our field_elems together (not carried)
fn fadd(a: FieldElem, b: FieldElem) -> FieldElem {
    let mut out: FieldElem = [0; 16];
    for i in 0..16 {
        out[i] = a[i] + b[i];
    }
    out
}

//Helper function for adding our field_elems together (not carried)
fn fsub(a: FieldElem, b: FieldElem) -> FieldElem {
    let mut out: FieldElem = [0; 16];
    for i in 0..16 {
        out[i] = a[i] - b[i];
    }
    out
}

//Helper function for multiplying two field elements together. This is partially carried (2 calls)
//And is close enough for the uses it is put to.
fn fmul(a: FieldElem, b: FieldElem) -> FieldElem {
    let mut out: FieldElem = [0; 16];
    let mut product: [i64; 31] = [0; 31];

    for i in 0..16 {
        for j in 0..16 {
            product[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        product[i] += 38 * product[i + 16];
    }
    out[..16].clone_from_slice(&product[..16]);
    // for i in 0..16 {
    //     out[i] = product[i];
    // }
    carry25519(&mut out);
    carry25519(&mut out);
    out
}

//Listing 2
//Invert a field_elem. This operation makes more sense in the context of abelian groups.
fn finverse(input: FieldElem) -> FieldElem {
    let mut c: FieldElem = [0; 16];
    c[..16].clone_from_slice(&input[..16]);

    for i in (0..=253).rev() {
        //This hardcodes the value of p
        c = fmul(c, c); //Because every bit of p is 1 except bits 2 and 4, we can just take the power...
        if i != 2 && i != 4 {
            c = fmul(c, input); //... except for those two bits
        }
    }
    c
}

//If bit is '1', swaps the values in p and q. Otherwise leaves them alone. Done using bitwise operators
//To provide the constant time execution needed to prevent side channel attacks.
fn swap25519(p: &mut FieldElem, q: &mut FieldElem, bit: i64) {
    let c = !(bit - 1);
    let mut t: i64;
    for i in 0..16 {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

//The inverse of unpack above, picks out portions of the (carried) 16 bytes and puts them together.
//Also runs the modulo p operation on the result in the body of the 0..2 for loop. At this point there are
//three options for the field_elem: It is either within < p, < 2p, or > 2p. Each of these three cases can be
//solved by taking the corresponding number of modulo p operations. The algorithm determines
//the correct number of modulo p operations to run in constant time by attempting all 3, and checking the carry bit
//in each case, and only successfully swapping into t if the values are correct
fn pack25519(input: FieldElem) -> U8_32 {
    let mut carry: i64;
    let mut m: FieldElem = [0; 16];
    let mut t: FieldElem = [0; 16];
    let mut output: U8_32 = [0; 32];

    t[..16].clone_from_slice(&input[..16]);

    carry25519(&mut t);
    carry25519(&mut t);
    carry25519(&mut t);

    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        carry = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        swap25519(&mut t, &mut m, 1 - carry);
    }

    for i in 0..16 {
        output[2 * i] = (t[i] & 0xff) as u8; //TODO Check data type conversions
        output[2 * i + 1] = (t[i] >> 8) as u8; //TODO Check data type conversions
    }

    output
}

//Listing 3

//A special value whose x coordinate equals 9.
const _9: U8_32 = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

//Performs scalar multiplication against a constant group element (9)
//Used to generate g^k by alice.
fn scalarmult_base(scalar: U8_32) -> U8_32 {
    scalarmult(scalar, _9)
}

//Generates a new key pair for cryptographic usage.
//First element is the public key, second element is the private key.
fn generate_keypair() -> (U8_32, U8_32) {
    let sk = random_bytes();
    let pk = scalarmult_base(sk);
    (pk, sk)
}

//Generates the shared secret.
//If this is the sender of a request (e.g. Alice in 2.3),
// - pk = Their public key (e.g. Bob's g^j)
// - sk = k, the random value generated for the shared secret
// - This method returns g^jk, to be used as a shared secret
//If this is the recipient of a request
// - pk = g^k, generated by alice.
// - sk = our private key (j)
// - This method returns g^kj, to be used as a shared secret
fn x25519(pk: U8_32, sk: U8_32) -> U8_32 {
    scalarmult(sk, pk)
}

//Helper function written by me to generate random bytes for k and the secret key.
fn random_bytes() -> U8_32 {
    let mut out = [0; 32];

    let mut r = rand::thread_rng();

    for i in 0..32 {
        out[i] = r.gen(); //Should be cryptographically secure, see: https://rust-random.github.io/rand/rand/rngs/struct.StdRng.html
    }

    out
}

//Listing 4
const _121665: FieldElem = [0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

//Multiplies a point and a scalar together, using the 255 bit number format, and optimized Montgomery's Ladder equations
//See the text for the derivation and explanation of the math.
//`scalar` is a random 32 byte integer
//`point` is the x coordinate of a point on the 25519 curve (Y is not used in the calculations)
fn scalarmult(scalar: U8_32, point: U8_32) -> U8_32 {
    let mut clamped: U8_32 = [0; 32];
    let mut bit: i64;
    let mut a: FieldElem = [0; 16];
    let mut b: FieldElem = [0; 16];
    let mut c: FieldElem = [0; 16];
    let mut d: FieldElem = [0; 16];
    let mut e: FieldElem;
    let mut f: FieldElem;
    let x: FieldElem;

    clamped[..31].clone_from_slice(&scalar[..31]);

    clamped[0] &= 0xf8; //set the 3 least significant bits to 0, ensures that this is a multiple of 8
    clamped[31] = (clamped[31] & 0x7f) | 0x40; //Set the most significant bit to 0 and second most to 1
                                               //Setting the most significant bit to 0 ensures that `clamped` is in the form h * k, where h = 8 and k
                                               //is some random value. The second most significant bit set to 1 enforces a constant time scalar multiply,
                                               //As otherwise the implementation could optimize away the first pass and leak the most significant bit.
    x = unpack25519(point);

    for i in 0..16 {
        b[i] = x[i];
        d[i] = 0;
        a[i] = 0;
        c[i] = 0;
    }
    a[0] = 1;
    d[0] = 1;

    //The variables have been initialized. Actually do the calculations for every bit in the
    //input.
    for i in (0..=254).rev() {
        bit = (clamped[i >> 3] as i64 >> (i & 7)) & 1;

        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);

        e = fadd(a, c);
        a = fsub(a, c);
        c = fadd(b, d);
        b = fsub(b, d);
        d = fmul(e, e);
        f = fmul(a, a);
        a = fmul(c, a);
        c = fmul(b, e);
        e = fadd(a, c);
        a = fsub(a, c);
        b = fmul(a, a);
        c = fsub(d, f);
        a = fmul(c, _121665);
        a = fadd(a, d);
        c = fmul(c, a);
        a = fmul(d, f);
        d = fmul(b, x);
        b = fmul(e, e);

        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);
    }
    //At this point we have the result in projective coordinates (X/Z) in a and c.
    //To turn them back into affine coordinates (just X), we have to divide the two values. Due to the
    //definition of abelian groups, this is just multiplication with the inverse:
    c = finverse(c);
    a = fmul(a, c);

    //Pack it up, send it off!
    pack25519(a)
}

//*************************** End listings ***************************

fn pack_u8_32_into_string(num: U8_32) -> String {
    let mut out = "".to_string();
    for i in (0..32).rev() {
        //go in big endian order
        out = format!("{}{:0<2x?}", out, num[i]);
    }
    out = out.replace("0x", ""); //I can probably make this better
    format!("0x{}", out)
}

fn main() {
    let (bob_pk, bob_sk) = generate_keypair();
    println!(
        "Bob's PK:              {:?}",
        pack_u8_32_into_string(bob_pk)
    );
    println!(
        "Bob's SK:              {:?}",
        pack_u8_32_into_string(bob_sk)
    );
    let (alice_pk, alice_sk) = generate_keypair();
    println!(
        "Alice's PK:            {:?}",
        pack_u8_32_into_string(alice_pk),
    );
    println!(
        "Alice's PK:            {:?}",
        pack_u8_32_into_string(alice_sk)
    );

    // From alice's perspective
    let alice_k = random_bytes();
    let shared_secret_a = x25519(bob_pk, alice_k);
    let alice_gk = scalarmult_base(alice_k);

    //from Bob's perspective:
    let shared_secret_b = x25519(alice_gk, bob_sk);

    println!(
        "Alice's shared secret: {:?}",
        pack_u8_32_into_string(shared_secret_a)
    );
    println!(
        "Bob's   shared secret: {:?}",
        pack_u8_32_into_string(shared_secret_b)
    );
}

//Because I like seeing passing tests 🥰
#[test]
fn test_shared_secret_gen() {
    //Bob, publishes 'bob_pk'
    let (bob_pk, bob_sk) = generate_keypair();

    //Alice, does the following calculations:
    let alice_k = random_bytes();
    let shared_secret_a = x25519(bob_pk, alice_k);
    let alice_gk = scalarmult_base(alice_k);
    //Sends alice_gk to bob.

    //Bob, receives alice's g^k and calculates his own shared secret:
    let shared_secret_b = x25519(alice_gk, bob_sk);

    //These are both equal.
    assert_eq!(shared_secret_a, shared_secret_b);
}
