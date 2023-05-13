use std::collections::BTreeMap;
use std::ops::Deref;

use ctap2_proto::extensions;
use ctap2_proto::prelude::*;
use ctap2_proto::Ctap2_2Authenticator;

extern crate ctap2_proto;

struct FidoKey(ctap_hid_fido2::FidoKeyHid);

impl Deref for FidoKey {
    type Target = ctap_hid_fido2::FidoKeyHid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Ctap2_2Authenticator for FidoKey {
    fn make_credential(&mut self, request: make::Request) -> Result<make::Response, make::Error> {
        let args = MakeCredentialArgsBuilder::new(
            &request.relying_party.id,
            request.client_data_hash.as_ref(),
        )
        .build();

        let attestation = match self.make_credential_with_args(&args) {
            Ok(attestation) => attestation,
            Err(e) => {
                todo!("unhandled error: {e}") // anyhow::Error requires manually
                                              // mapping
            }
        };

        let format = if !attestation.flags_attested_credential_data_included {
            FormatIdentifier::None
        } else {
            unimplemented!("do not support attestation yet")
        };

        let authenticator_data = attestation.auth_data.as_slice().try_into().unwrap();

        let unsigned_extension_outputs: BTreeMap<_, _> = attestation
            .extensions
            .into_iter()
            .filter_map(|extension| -> Option<(extensions::Identifier, Vec<u8>)> {
                match extension {
                    CredentialExtension::CredBlob(_) => {
                        todo!()
                    }
                    CredentialExtension::CredProtect(_) => {
                        todo!()
                    }
                    CredentialExtension::HmacSecret(_) => {
                        todo!()
                    }
                    CredentialExtension::LargeBlobKey(_) => {
                        todo!()
                    }
                    CredentialExtension::MinPinLength(_) => {
                        todo!()
                    }
                }
            })
            .collect();

        let unsigned_extension_outputs = if !unsigned_extension_outputs.is_empty() {
            Some(unsigned_extension_outputs)
        } else {
            None
        };

        Ok(make::Response {
            format,
            authenticator_data,
            enterprise_attestation: None,
            large_blob_key: None,
            unsigned_extension_outputs,
        })
    }

    fn get_assertion(request: get::Request) -> Result<get::Response, get::Error> {
        todo!()
    }

    fn get_info(&self) -> device::Info {
        todo!()
    }

    fn client_pin(request: client_pin::Request) -> Result<client_pin::Response, client_pin::Error> {
        todo!()
    }

    fn reset() -> Result<(), reset::Error> {
        todo!()
    }

    fn selection() -> Result<(), ctap2_proto::authenticator::selection::Error> {
        todo!()
    }
}

use ctap_hid_fido2::fidokey::CredentialExtension;
use ctap_hid_fido2::{
    fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
    verifier, Cfg, FidoKeyHidFactory,
};
use fido_common::attestation::FormatIdentifier;

fn main() {
    let rpid = "reg-auth-example-app";
    let pin = get_input_with_message("input PIN:");

    println!("Register");
    // create `challenge`
    let challenge = verifier::create_challenge();

    // create `MakeCredentialArgs`
    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(&pin)
        .build();

    let mut cfg = Cfg::init();
    cfg.enable_log = false;

    // create `FidoKeyHid`
    let device = FidoKeyHidFactory::create(&cfg).unwrap();

    if device.get_info().unwrap().force_pin_change {
        device.set_new_pin("1234").unwrap();
    }

    // get `Attestation` Object
    let attestation = device
        .make_credential_with_args(&make_credential_args)
        .unwrap();
    println!("- Register Success");

    // verify `Attestation` Object
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if !verify_result.is_success {
        println!("- ! Verify Failed");
        return;
    }

    // store Credential Id and Publickey
    let userdata_credential_id = verify_result.credential_id;
    let userdata_credential_public_key = verify_result.credential_public_key;

    println!("Authenticate");
    // create `challenge`
    let challenge = verifier::create_challenge();

    // create `GetAssertionArgs`
    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(&pin)
        .credential_id(&userdata_credential_id)
        .build();

    // get `Assertion` Object
    let assertions = device.get_assertion_with_args(&get_assertion_args).unwrap();
    println!("- Authenticate Success");

    // verify `Assertion` Object
    if !verifier::verify_assertion(
        rpid,
        &userdata_credential_public_key,
        &challenge,
        &assertions[0],
    ) {
        println!("- ! Verify Assertion Failed");
    }
}

pub fn get_input() -> String {
    let mut word = String::new();
    std::io::stdin().read_line(&mut word).ok();
    return word.trim().to_string();
}

pub fn get_input_with_message(message: &str) -> String {
    println!("{}", message);
    let input = get_input();
    println!();
    input
}
