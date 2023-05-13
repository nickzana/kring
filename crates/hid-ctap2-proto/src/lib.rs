use ctap2_proto::{prelude::*, Ctap2_2Authenticator};
use ctaphid::types::Command;

pub struct Device<D: ctaphid::HidDevice>(ctaphid::Device<D>);

impl<D: ctaphid::HidDevice> Device<D> {
    fn send_raw(&self, command: Command, bytes: &[u8]) -> Result<Vec<u8>, ctaphid::error::Error> {
        self.0.ctap2(command.into(), bytes)
    }

    fn send<Req, Res>(&self, req: Req) -> Result<Res, ctaphid::error::Error>
    where
        Req: serde::Serialize,
        Res: for<'de> serde::Deserialize<'de>,
    {
        let command = Command::Cbor;
        let mut data: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(&req, &mut data).map_err(|e| match e {
            ciborium::ser::Error::Io(_) => ctaphid::error::RequestError::IncompleteWrite,
            ciborium::ser::Error::Value(desc) => {
                ctaphid::error::RequestError::PacketSendingFailed(desc.into())
            }
        })?;

        let response = self.0.ctap2(command.into(), &data)?;

        match ciborium::de::from_reader(response.as_slice()) {
            Ok(res) => Ok(res),
            Err(e) => match e {
                ciborium::de::Error::Io(_) => todo!(),
                ciborium::de::Error::Syntax(_) => todo!(),
                ciborium::de::Error::Semantic(_, _) => todo!(),
                ciborium::de::Error::RecursionLimitExceeded => todo!(),
            },
        }
    }
}

impl<D> Ctap2_2Authenticator for Device<D>
where
    D: ctaphid::HidDevice,
{
    fn make_credential(&mut self, request: make::Request) -> Result<make::Response, make::Error> {
        // TODO: How the heck am i supposed to handle errors???
        self.send(&request).map_err(|e| match e {
            ctaphid::error::Error::CommandError(e) => match e {
                ctaphid::error::CommandError::CborError(_) => todo!(),
                ctaphid::error::CommandError::InvalidPingData => todo!(),
                ctaphid::error::CommandError::NotSupported(_) => todo!(),
            },
            ctaphid::error::Error::RequestError(e) => match e {
                ctaphid::error::RequestError::IncompleteWrite => todo!(),
                ctaphid::error::RequestError::MessageFragmentationFailed(_) => todo!(),
                ctaphid::error::RequestError::PacketSendingFailed(_) => todo!(),
                ctaphid::error::RequestError::PacketSerializationFailed(_) => todo!(),
            },
            ctaphid::error::Error::ResponseError(e) => match e {
                ctaphid::error::ResponseError::CommandFailed(_) => todo!(),
                ctaphid::error::ResponseError::MessageDefragmentationFailed(_) => todo!(),
                ctaphid::error::ResponseError::PacketParsingFailed(_) => todo!(),
                ctaphid::error::ResponseError::PacketReceivingFailed(_) => todo!(),
                ctaphid::error::ResponseError::Timeout => todo!(),
                ctaphid::error::ResponseError::MissingErrorCode => todo!(),
                ctaphid::error::ResponseError::UnexpectedCommand { expected, actual } => todo!(),
                ctaphid::error::ResponseError::UnexpectedKeepAlive(_) => todo!(),
                ctaphid::error::ResponseError::UnexpectedResponseData(_) => todo!(),
            },
        })
    }

    fn get_assertion(request: get::Request) -> Result<get::Response, get::Error> {
        todo!()
    }

    fn get_info(&self) -> device::Info {
        let info = self.send_raw(Command::Cbor, &[1u8, 4]).unwrap();
        println!("info: {info:#?}");
        let info: device::Info =
            ciborium::de::from_reader::<device::Info, _>(info.as_slice()).unwrap();
        info
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

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use ctap2_proto::Ctap2_2Authenticator;
    use ctaphid::{
        error::{RequestError, ResponseError},
        types::Command,
    };
    struct HidDevice(hidapi::HidDevice);
    #[derive(Debug)]
    struct HidDeviceInfoMy(hidapi::DeviceInfo);

    impl ctaphid::HidDeviceInfo for HidDeviceInfoMy {
        fn vendor_id(&self) -> u16 {
            hidapi::DeviceInfo::vendor_id(&self.0)
        }

        fn product_id(&self) -> u16 {
            hidapi::DeviceInfo::product_id(&self.0)
        }

        fn path(&self) -> std::borrow::Cow<'_, str> {
            let cstr: &CStr = hidapi::DeviceInfo::path(&self.0);
            let s = cstr.to_str().unwrap();
            std::borrow::Cow::from(s)
        }
    }

    impl ctaphid::HidDevice for HidDevice {
        type Info = HidDeviceInfoMy;

        fn send(&self, data: &[u8]) -> Result<(), ctaphid::error::RequestError> {
            println!("sending bytes: {data:#?}");
            hidapi::HidDevice::write(&self.0, data)
                .map_err(|e| RequestError::PacketSendingFailed(e.into()))?;
            Ok(())
        }

        fn receive<'a>(
            &self,
            buffer: &'a mut [u8],
            timeout: Option<std::time::Duration>,
        ) -> Result<&'a [u8], ctaphid::error::ResponseError> {
            println!("reading bytes");
            let duration = if let Some(timeout) = timeout {
                i32::try_from(timeout.as_millis())
                    .map_err(|err| ResponseError::PacketReceivingFailed(err.into()))?
            } else {
                -1
            };
            let n = self
                .0
                .read_timeout(buffer, duration)
                .map_err(|err| ResponseError::PacketReceivingFailed(err.into()))?;
            if n == buffer.len() {
                Ok(&buffer[1..n])
            } else if n == 0 {
                Err(ResponseError::Timeout)
            } else {
                Ok(&buffer[..n])
            }
        }
    }

    #[test]
    fn get_info() {
        let hidapi = hidapi::HidApi::new().unwrap();
        let devices = hidapi.device_list();
        for device_info in devices {
            let hid_device = hidapi::DeviceInfo::open_device(&device_info, &hidapi);
            let hid_device = match hid_device {
                Ok(hid_device) => hid_device,
                Err(e) => {
                    println!("error: {e:#?}");
                    continue;
                }
            };
            let device = HidDevice(hid_device);
            let device =
                ctaphid::Device::new(device, HidDeviceInfoMy(device_info.to_owned())).unwrap();
            let device = super::Device(device);
            println!("info: {:#?}", device.0.ctap2(Command::Cbor.into(), &[]));
        }
        assert!(false);
    }

    #[test]
    fn quickstart() {}
}
