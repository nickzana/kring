#![feature(let_chains)]
extern crate ctap2_proto;

<<<<<<< Updated upstream
use std::collections::HashMap;
=======
use std::collections::BTreeMap;
>>>>>>> Stashed changes

use bounded_vec::BoundedVec;
use ctap2_proto::authenticator::Sha256Hash;
// Recommended
use ctap2_proto::prelude::*;

use ctap2_proto::{
    authenticator,
    prelude::{
        client_pin::AuthProtocolVersion,
        device::{Aaguid, Version},
    },
};
use fido_common::credential::public_key::{RelyingPartyEntity, UserEntity};
use fido_common::{
    attestation,
    credential::{self, public_key::Parameters},
    registry::algorithms::Signature,
    Transport,
};

const AAGUID: Aaguid = Aaguid::from(*b"\xed\xeeZow\xdc\xf5\xadZ\xe3\xd7\xb8\xf5\xf6\xf7\xd7");
const VERSION: usize = 1;
const SUPPORTED_AUTH_PROTOCOL_VERSIONS: [AuthProtocolVersion; 1] = [AuthProtocolVersion::Two];
const SUPPORTED_PUBLIC_KEY_ALGORITHMS: [Parameters; 1] = [Parameters {
    credential_type: credential::Type::PublicKey,
    algorithm: Signature::Ed25519EddsaSha512Raw,
}];

struct VirtualAuthenticator<R, W>
where
    R: std::io::Read + Send,
    W: std::io::Write + Send,
{
    pin: Option<Vec<u8>>,
    input: R,
    output: W,
}

enum Presence {
    Present,
    NotPresent,
}

impl<R, W> VirtualAuthenticator<R, W>
where
    R: std::io::Read + Send,
    W: std::io::Write + Send,
{
    fn verify_presence(reader: &mut R, writer: &mut W) -> Result<Presence, std::io::Error> {
        write!(writer, "Allow this operation? [Y/n]:")?;
        let mut input = <[u8; 1]>::default();
        reader.read_exact(&mut input)?;
        writeln!(writer)?;
        if input[0] == b'Y' {
            Ok(Presence::Present)
        } else {
            Ok(Presence::NotPresent)
        }
    }
}

impl<R, W> Ctap2_2Authenticator for VirtualAuthenticator<R, W>
where
    R: std::io::Read + Send,
    W: std::io::Write + Send,
{
    fn make_credential(&mut self, request: make::Request) -> Result<make::Response, make::Error> {
        // If authenticator supports either pinUvAuthToken or clientPin features and the
        // platform sends a zero length pinUvAuthParam:
        if let Some(options) = self.get_info().options &&
            (options.contains_key(&device::OptionId::PinUvAuthToken) || options.contains_key(&device::OptionId::ClientPin)) && request.pin_uv_auth_param.len() == 0
        {
            // Request evidence of user interaction in an authenticator-specific way (e.g., flash
            // the LED light).
            // If the user declines permission, or the operation times out, then end the operation
            // by returning CTAP2_ERR_OPERATION_DENIED.
            let Ok(Presence::Present) = Self::verify_presence(&mut self.input, &mut self.output) else {
                return Err(make::Error::OperationDenied);
            };
       
            // If evidence of user interaction is provided in this step then return either
            // CTAP2_ERR_PIN_NOT_SET if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been
            // set.
            if self.pin.is_some() {
                return Err(make::Error::PinInvalid);
            } else {
                return Err(make::Error::PinNotSet);
            }
        }

        // If the pinUvAuthParam parameter is present:
        debug_assert!(request.pin_uv_auth_param.len() > 0);

        // If the pinUvAuthProtocol parameter’s value is not supported, return
        // CTAP1_ERR_INVALID_PARAMETER error.
        // If the pinUvAuthProtocol parameter is absent, return
        // CTAP2_ERR_MISSING_PARAMETER error.
        let Some(auth_protocol_version) = request.pin_uv_auth_protocol_version else { return Err(make::Error::MissingParameter) };
        if !SUPPORTED_AUTH_PROTOCOL_VERSIONS.contains(&auth_protocol_version) {
            return Err(make::Error::InvalidParameter);
        }

        // Filter out any invalid or unsupported params, then take the first valid one.

        // TODO: The following NOTE from the specs refers to the following loop, however
        // this loop only iterates over the algorithms until a match is found.
        //
        // The only risk I can imagine is enumerating the supported algorithms of the
        // authenticator, which doesn't seem that important to protect against.
        //
        // NOTE: This loop chooses the first occurrence of an algorithm identifier
        // supported by this authenticator but always iterates over every
        // element of pubKeyCredParams to validate them.

        // Validate pubKeyCredParams with the following steps:
        // 1. For each element of pubKeyCredParams:
        let Some(public_key_algorithm) = request.public_key_credential_params.into_iter().filter(|params| {
            // TODO: Ensure that invalid params are unrepresentable
            // If the element is missing required members, including members that are mandatory
            // only for the specific type, then return an error, for example
            // CTAP2_ERR_INVALID_CBOR.

            // TODO: What would it mean for a credential to have the wrong type?    
            // If the values of any known members have the wrong type then return an error, for
            // example CTAP2_ERR_CBOR_UNEXPECTED_TYPE.

            // If the element specifies an algorithm that is supported by the authenticator, and no
            // algorithm has yet been chosen by this loop, then let the algorithm specified by the
            // current element be the chosen algorithm.
            return SUPPORTED_PUBLIC_KEY_ALGORITHMS.contains(params);
        }).next() else {
            // If the loop completes and no algorithm was chosen then return
            // CTAP2_ERR_UNSUPPORTED_ALGORITHM.
            return Err(make::Error::UnsupportedAlgorithm);
        };

        // No attestation
        let format = attestation::FormatIdentifier::None;
        // No enterprise attestation
        let enterprise_attestation = None;

        // If the "uv" option is absent, let the "uv" option be treated as being present
        // with the value false. (This is the default)
        let mut user_verification = false;
        let mut discoverable_credential = false;
        let mut user_presence = true;

        let authenticator_data = authenticator::Data {
            relying_party_id_hash: todo!(),
            user_is_present: todo!(),
            user_is_verified: todo!(),
            signature_counter: todo!(),
            attested_credential_data: todo!(),
            extensions: None,
        };

        if let Some(req_options) = request.options {
            // If the pinUvAuthParam is present, let the "uv" option be treated as being
            // present with the value false.
            if let Some(true) = req_options.get(&make::OptionKey::UserVerification) {}
        }

        Ok(make::Response {
            format,
            authenticator_data,
            enterprise_attestation,
            large_blob_key: None,
            unsigned_extension_outputs: None,
        })
    }

    fn get_assertion(request: get::Request) -> Result<get::Response, get::Error> {
        todo!()
    }

    fn get_info(&self) -> device::Info {
        device::Info {
            versions: [Version::Fido2_1].into_iter().collect(),
            extensions: None,
            aaguid: AAGUID,
            options: None,
            max_message_size: None,
            pin_uv_auth_protocols: Some(SUPPORTED_AUTH_PROTOCOL_VERSIONS.into()),
            max_credential_count_in_list: None,
            max_credential_id_length: None,
            transports: Some([Transport::Internal].into_iter().collect()),
            algorithms: Some(SUPPORTED_PUBLIC_KEY_ALGORITHMS.into()),
            max_serialized_large_blob_array_size: None,
            force_pin_change: Some(self.pin.is_none()),
            min_pin_length: None,
            firmware_version: Some(VERSION),
            max_cred_blob_length: None,
            max_rpids_for_set_min_pin_length: None,
            preferred_platform_uv_attempts: None,
            uv_modality: None,
            certifications: None,
            remaining_discoverable_credentials: None,
            vendor_prototype_config_commands: None,
        }
    }

    fn client_pin(request: client_pin::Request) -> Result<client_pin::Response, client_pin::Error> {
        todo!()
    }

    fn reset() -> Result<(), reset::Error> {
        todo!()
    }

    fn selection() -> Result<(), selection::Error> {
        todo!()
    }
}

fn main() {
    let pin = None;

    let authenticator = VirtualAuthenticator {
        pin,
        input: std::io::stdin(),
        output: std::io::stdout(),
    };

    let client_data_hash = Sha256Hash([0; 32]);
    let relying_party = RelyingPartyEntity {
        id: "example.com".into(),
        name: Some("Example Inc.".into()),
    };
    let user_entity = UserEntity {
        id: BoundedVec::from_vec([1u8; 64].into()).unwrap(),
        name: Some("user@example.com".into()),
        display_name: Some("Example User".into()),
    };

    // Get authenticator info
    let info = authenticator.get_info();

    // Make a new discoverable credential
    let options = HashMap::from([
        (make::OptionKey::UserVerification, true),
        (make::OptionKey::Discoverable, true),
        (make::OptionKey::UserPresence, false),
    ]);
    let request = make::Request {
        client_data_hash: &client_data_hash,
        relying_party: &relying_party,
        user: &user_entity,
        public_key_credential_params: &SUPPORTED_PUBLIC_KEY_ALGORITHMS,
        exclude_list: None,
        extensions: None,
        options: Some(&options),
        pin_uv_auth_param: (),
        pin_uv_auth_protocol_version: (),
        enterprise_attestation: None,
    };
    authenticator.make_credential(request);
}
