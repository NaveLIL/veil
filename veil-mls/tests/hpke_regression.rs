use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType},
    OpenMlsProvider,
};

fn veil_hpke_config() -> HpkeConfig {
    HpkeConfig(
        HpkeKemType::DhKem25519,
        HpkeKdfType::HkdfSha256,
        HpkeAeadType::AesGcm128,
    )
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("valid test-vector hex")
}

#[test]
fn rfc9180_a1_base_mode_known_answer_test() {
    // RFC 9180 Appendix A.1.1 is the exact KEM/KDF/AEAD combination used by
    // Veil's sole MLS ciphersuite. Keep this at the OpenMLS provider boundary
    // so dependency upgrades cannot silently change its cryptographic output.
    let provider = OpenMlsRustCrypto::default();
    let crypto = provider.crypto();
    let key_pair = crypto
        .derive_hpke_keypair(
            veil_hpke_config(),
            &decode_hex("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"),
        )
        .expect("derive RFC recipient key pair");

    assert_eq!(
        hex::encode(&*key_pair.private),
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"
    );
    assert_eq!(
        hex::encode(&key_pair.public),
        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
    );

    let kem_output = decode_hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    let ciphertext = decode_hex(
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9\
         6d8770ac83d07bea87e13c512a",
    );
    let input = HpkeCiphertext {
        kem_output: kem_output.clone().into(),
        ciphertext: ciphertext.clone().into(),
    };
    let info = decode_hex("4f6465206f6e2061204772656369616e2055726e");
    let aad = decode_hex("436f756e742d30");

    assert_eq!(
        crypto
            .hpke_open(veil_hpke_config(), &input, &key_pair.private, &info, &aad,)
            .expect("open RFC ciphertext"),
        decode_hex("4265617574792069732074727574682c20747275746820626561757479")
    );

    let exported = crypto
        .hpke_setup_receiver_and_export(
            veil_hpke_config(),
            &kem_output,
            &key_pair.private,
            &info,
            b"TestContext",
            32,
        )
        .expect("export RFC receiver secret");
    assert_eq!(
        hex::encode(&*exported),
        "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931"
    );

    let mut tampered = ciphertext;
    *tampered.last_mut().expect("non-empty ciphertext") ^= 1;
    let tampered = HpkeCiphertext {
        kem_output: kem_output.into(),
        ciphertext: tampered.into(),
    };
    assert!(
        crypto
            .hpke_open(
                veil_hpke_config(),
                &tampered,
                &key_pair.private,
                &info,
                &aad,
            )
            .is_err(),
        "modified authentication tag must be rejected"
    );
}

#[test]
fn hpke_0_6_ciphertext_remains_readable() {
    // Golden generated once with the published, unmodified
    // openmls_rust_crypto 0.4.4 crate (hpke-rs 0.6.1) using only synthetic
    // test material. The recipient key is deterministically derived below;
    // the captured encapsulation is a one-time test vector. It proves
    // old-provider -> new-provider wire compatibility without compiling the
    // vulnerable graph in CI.
    let provider = OpenMlsRustCrypto::default();
    let crypto = provider.crypto();
    let ikm: Vec<u8> = (0u8..32).collect();
    let key_pair = crypto
        .derive_hpke_keypair(veil_hpke_config(), &ikm)
        .expect("derive compatibility key pair");

    assert_eq!(
        hex::encode(&*key_pair.private),
        "91f7a467df4ef97053ec2a47b6e619f632df9547bb009fd0bcc747909f1b7bd4"
    );
    assert_eq!(
        hex::encode(&key_pair.public),
        "b1f1b840de7a3241b02748cf9b05b74dc8c5e8451298738817bd76aa8ebe8c2b"
    );

    let legacy = HpkeCiphertext {
        kem_output: decode_hex("cab11407046c2aaa894ec5e5961a1e6d62ffd25e6e3f986517b2048a77a52934")
            .into(),
        ciphertext: decode_hex(
            "daf89d1b05ff4cfa7249d95021c856ffe272f7f4b40c5a231889c059bca3c117\
             9f63494626c6ee",
        )
        .into(),
    };

    assert_eq!(
        crypto
            .hpke_open(
                veil_hpke_config(),
                &legacy,
                &key_pair.private,
                b"veil-hpke-kat-v1",
                b"veil-aad-v1",
            )
            .expect("open hpke-rs 0.6.1 ciphertext"),
        b"old-provider-ciphertext"
    );
}
