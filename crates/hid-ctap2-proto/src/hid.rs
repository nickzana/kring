use ctap2_proto::Command;
use device::{DeviceInfo, HidDevice};

pub struct HidAuthenticator<D: ctaphid::HidDevice = HidDevice>(ctaphid::Device<D>);

impl TryFrom<hidapi::HidDevice> for HidAuthenticator<HidDevice> {
    type Error = ctaphid::error::Error;

    fn try_from(device: hidapi::HidDevice) -> Result<Self, Self::Error> {
        let info = device
            .get_device_info()
            .map_err(|e| ctaphid::error::RequestError::PacketSendingFailed(Box::new(e)))?;
        let device = ctaphid::Device::new(HidDevice(device), DeviceInfo(info))?;
        Ok(Self(device))
    }
}

mod device {
    //! Provides wrapper types for `hidapi` device types that implement required
    //! `ctaphid` interfaces.
    use std::borrow::Cow;

    pub struct HidDevice(pub hidapi::HidDevice);
    #[derive(Debug)]
    pub struct DeviceInfo(pub hidapi::DeviceInfo);

    impl ctaphid::HidDevice for HidDevice {
        type Info = DeviceInfo;

        fn send(&self, data: &[u8]) -> Result<(), ctaphid::error::RequestError> {
            self.0
                .write(data)
                .map_err(|e| ctaphid::error::RequestError::PacketSendingFailed(e.into()))?;
            Ok(())
        }

        fn receive<'a>(
            &self,
            buffer: &'a mut [u8],
            timeout: Option<std::time::Duration>,
        ) -> Result<&'a [u8], ctaphid::error::ResponseError> {
            let timeout_millis: i32 = match timeout {
                Some(timeout) => timeout.as_millis() as i32,
                None => -1,
            };
            let count = self
                .0
                .read_timeout(buffer, timeout_millis)
                .map_err(|e| match e {
                    hidapi::HidError::HidApiError { message } => {
                        ctaphid::error::ResponseError::PacketReceivingFailed(message.into())
                    }
                    _ => todo!(),
                })?;

            Ok(&buffer[..count])
        }
    }

    impl ctaphid::HidDeviceInfo for DeviceInfo {
        fn vendor_id(&self) -> u16 {
            self.0.vendor_id()
        }

        fn product_id(&self) -> u16 {
            self.0.product_id()
        }

        fn path(&self) -> std::borrow::Cow<'_, str> {
            let path = self
                .0
                .path()
                .to_str()
                .expect("Device path must be valid UTF-8.");
            Cow::from(path)
        }
    }
}

impl<D: ctaphid::HidDevice> HidAuthenticator<D> {
    fn send_ctap1_raw(&self, bytes: &[u8]) -> Result<Vec<u8>, ctaphid::error::Error> {
        self.0.ctap1(bytes)
    }

    fn send_ctap2_raw(
        &self,
        command: Command,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ctaphid::error::Error> {
        self.0.ctap2(command as u8, bytes)
    }

    pub fn send<Req, Res>(&self, command: Command, req: Req) -> Result<Res, ctaphid::error::Error>
    where
        Req: serde::Serialize,
        Res: for<'de> serde::Deserialize<'de>,
    {
        let mut data: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(&req, &mut data).map_err(|e| match e {
            ciborium::ser::Error::Io(_) => ctaphid::error::RequestError::IncompleteWrite,
            ciborium::ser::Error::Value(desc) => {
                ctaphid::error::RequestError::PacketSendingFailed(desc.into())
            }
        })?;

        let response = self.send_ctap2_raw(command, &data)?;

        match ciborium::de::from_reader(response.as_slice()) {
            Ok(response) => Ok(response),
            // TODO: Improve error handling
            Err(e) => {
                println!("ERROR: {e}");
                todo!()
            }
        }
    }
}
