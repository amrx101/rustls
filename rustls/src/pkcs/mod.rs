use crate::msgs::enums::{SignatureAlgorithm, SignatureScheme};
use libloading as lib;

/// A Pkcs Struct that holds all data 
/// prudent to an HSM
pub struct Pkcs {
    slot_id: i32,
    user_pin: String,
    lib_path: String,
    scheme: SignatureScheme,
    sigalg: SignatureAlgorithm,
    lib: lib::Library,
}

impl Pkcs {
    /// return a Pkcs
    pub fn new(slot_id: i32, user_pin: String, lib_path:String, scheme: SignatureScheme, sigalg: SignatureAlgorithm) -> Pkcs {
        let lib = lib::Library::new(lib_path.clone()).unwrap();
        Pkcs{
            slot_id,
            user_pin,
            lib_path,
            scheme,
            sigalg,
            lib,
        }
    }

    /// custom ather signer
    pub fn ather_sign(self, data: Vec<u8>) -> Vec<u8>{
        let mut v = vec!(1, 2, 3);
        v
    }
}