use tweet_nacl_rust::{generate_keypair, random_bytes, x25519, scalarmult_base};

fn pack_u8_32_into_string(num: [u8; 32]) -> String {
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
