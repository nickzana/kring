#![cfg_attr(test, feature(split_array, lazy_cell))]

use ctap2_proto::{prelude::*, Ctap2_2Authenticator};
use hid::HidAuthenticator;

pub mod hid;

impl<D: ctaphid::HidDevice> Ctap2_2Authenticator for HidAuthenticator<D> {
    fn make_credential(&mut self, request: make::Request) -> Result<make::Response, make::Error> {
        Ok(self
            .send(Command::AuthenticatorMakeCredential, request)
            .unwrap()) // TODO: Properly parse/convert errors
    }

    fn get_assertion(&mut self, request: get::Request) -> Result<get::Response, get::Error> {
        Ok(self
            .send(Command::AuthenticatorGetAssertion, request)
            .unwrap())
    }

    fn get_info(&self) -> device::Info {
        self.send(Command::AuthenticatorGetInfo, ()).unwrap()
    }

    fn client_pin(
        &mut self,
        _request: client_pin::Request,
    ) -> Result<client_pin::Response, client_pin::Error> {
        todo!()
    }

    fn reset(&mut self) -> Result<(), reset::Error> {
        Ok(self.send(Command::AuthenticatorReset, ()).unwrap())
    }

    fn selection(&mut self) -> Result<(), ctap2_proto::authenticator::selection::Error> {
        todo!()
    }

    fn bio_enrollment(
        &mut self,
        request: bio_enrollment::Request,
    ) -> Result<bio_enrollment::Response, bio_enrollment::Error> {
        todo!()
    }

    fn credential_management(
        &mut self,
        request: management::Request,
    ) -> Result<management::Response, management::Error> {
        Ok(self
            .send(Command::AuthenticatorCredentialManagement, request)
            .unwrap())
    }

    fn authenticator_config(&mut self, request: config::Request) -> Result<(), config::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    extern crate hidapi;

    use std::{
        borrow::Cow,
        collections::BTreeSet,
        sync::{LazyLock, Mutex},
    };

    use crate::hid::HidAuthenticator;
    use ctap2_proto::prelude::{credential::public_key, *};
    use rand::{distributions, Rng};

    static AUTHENTICATOR: LazyLock<Mutex<Option<HidAuthenticator>>> =
        LazyLock::new(|| Mutex::new(get_authenticator()));

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn get_authenticator() -> Option<HidAuthenticator> {
        let hidapi = hidapi::HidApi::new().unwrap();
        for info in hidapi.device_list() {
            let Ok(device) = info.open_device(&hidapi) else {
                continue;
            };
            let Ok(authenticator) = device.try_into() else { continue };
            return Some(authenticator);
        }

        None
    }

    #[test]
    fn test_get_info() {
        init();

        let guard = AUTHENTICATOR.lock().unwrap();
        let authenticator = guard.as_ref().unwrap();

        let info = authenticator.get_info();
        println!("deserialized: {:#?}", info);
    }

    #[test]
    fn make_credential() {
        init();

        let mut guard = AUTHENTICATOR.lock().unwrap();
        let authenticator = guard.as_mut().unwrap();

        let info = authenticator.get_info();

        let client_data_hash: Vec<u8> = rand::thread_rng()
            .sample_iter(&distributions::Standard)
            .take(32)
            .collect();

        let user_id = rand::thread_rng()
            .sample_iter(&distributions::Standard)
            .take(32)
            .collect();

        let rp = public_key::RelyingPartyEntity {
            id: "com.example".to_string(),
            name: Some("Example Inc.".into()),
        };

        let user = public_key::UserEntity {
            id: user_id,
            name: Some("example_user".to_string()),
            display_name: Some("Example User".to_string()),
        };

        let pub_key_params: BTreeSet<_> = info.algorithms.unwrap().into_iter().collect();

        let options = [(make::OptionKey::Discoverable, true)].into();

        let req = make::Request::builder()
            .client_data_hash(Cow::Borrowed(client_data_hash.split_array_ref::<32>().0))
            .relying_party(Cow::Borrowed(&rp))
            .user(Cow::Borrowed(&user))
            .public_key_credential_params(Cow::Borrowed(&pub_key_params))
            .options(Cow::Borrowed(&options))
            .build();

        println!("request: {req:#?}");
        let response = authenticator.make_credential(req);
        println!("response: {response:#?}");

        let req = get::Request {
            relying_party_id: &rp.id,
            client_data_hash: client_data_hash.as_slice().try_into().unwrap(),
            allow_list: None,
            extensions: None,
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol_version: None,
        };

        println!("request: {req:#?}");
        let response = authenticator.get_assertion(req);
        println!("response: {response:#?}");
    }
}
