#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Some(bytes)=data.get(..64) {let _=withcrypt_core::Header::parse(bytes.try_into().unwrap());}
    if let Some(bytes)=data.get(..13) {let raw=bytes.try_into().unwrap();let _=withcrypt_core::format::RecordHeader::parse(raw,0);let _=withcrypt_core::format::RecordHeader::parse(raw,1);}
});
