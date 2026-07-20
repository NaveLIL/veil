/// Generated Protobuf types from veil-proto .proto files.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/veil.v1.rs"));
}

#[cfg(test)]
mod tests {
    use super::proto;
    use prost::Message;

    #[test]
    fn websocket_auth_v3_wire_numbers_are_frozen() {
        // Tiny values below are deliberately not semantically valid auth
        // material; this test freezes protobuf numbers only. The native v3
        // preparer owns the fail-closed length, origin, key, and proof checks.
        assert_eq!(proto::WsRegistrationIntentV3::Unspecified as i32, 0);
        assert_eq!(proto::WsRegistrationIntentV3::Existing as i32, 1);
        assert_eq!(proto::WsRegistrationIntentV3::Open as i32, 2);
        assert_eq!(proto::WsRegistrationIntentV3::Pass as i32, 3);
        assert_eq!(proto::WsAuthFailureReasonV3::Unspecified as i32, 0);
        assert_eq!(proto::WsAuthFailureReasonV3::AuthenticationFailed as i32, 1);
        assert_eq!(proto::WsAuthFailureReasonV3::RegistrationClosed as i32, 2);
        assert_eq!(
            proto::WsAuthFailureReasonV3::NodeAccessPassInvalid as i32,
            3
        );

        let challenge = proto::AuthChallengeV3 {
            protocol_version: 3,
            server_ephemeral: vec![1],
            canonical_node_origin: "x".to_owned(),
        };
        assert_eq!(
            challenge.encode_to_vec(),
            [0x08, 0x03, 0x12, 0x01, 0x01, 0x1a, 0x01, b'x']
        );

        let response = proto::AuthResponseV3 {
            protocol_version: 3,
            identity_key: vec![1],
            signing_key: vec![2],
            account_proof_signature: vec![3],
            device_id: vec![4],
            device_name: "d".to_owned(),
            client_version: "c".to_owned(),
            device_binding: Some(proto::DeviceBindingV1 {
                device_id: vec![5],
                ..Default::default()
            }),
            device_proof_signature: vec![6],
            registration_intent: proto::WsRegistrationIntentV3::Pass as i32,
            node_access_pass: vec![7],
        };
        assert_eq!(
            response.encode_to_vec(),
            [
                0x08, 0x03, 0x12, 0x01, 0x01, 0x1a, 0x01, 0x02, 0x22, 0x01, 0x03, 0x2a, 0x01, 0x04,
                0x32, 0x01, b'd', 0x3a, 0x01, b'c', 0x42, 0x03, 0x0a, 0x01, 0x05, 0x4a, 0x01, 0x06,
                0x50, 0x03, 0x5a, 0x01, 0x07,
            ]
        );

        let result = proto::AuthResultV3 {
            protocol_version: 3,
            success: true,
            user_id: Some("u".to_owned()),
            error_message: Some("e".to_owned()),
            per_device_secure: true,
            device_binding_version: 1,
            device_binding_status: proto::DeviceBindingStatus::Active as i32,
            failure_reason: proto::WsAuthFailureReasonV3::NodeAccessPassInvalid as i32,
            canonical_node_origin: "o".to_owned(),
        };
        assert_eq!(
            result.encode_to_vec(),
            [
                0x08, 0x03, 0x10, 0x01, 0x1a, 0x01, b'u', 0x22, 0x01, b'e', 0x28, 0x01, 0x30, 0x01,
                0x38, 0x01, 0x40, 0x03, 0x4a, 0x01, b'o',
            ]
        );

        for (payload, expected) in [
            (
                proto::envelope::Payload::AuthChallengeV3(Default::default()),
                vec![0x72, 0x00],
            ),
            (
                proto::envelope::Payload::AuthResponseV3(Default::default()),
                vec![0x7a, 0x00],
            ),
            (
                proto::envelope::Payload::AuthResultV3(Default::default()),
                vec![0x82, 0x01, 0x00],
            ),
        ] {
            let envelope = proto::Envelope {
                payload: Some(payload),
                ..Default::default()
            };
            assert_eq!(envelope.encode_to_vec(), expected);
        }
    }
}
