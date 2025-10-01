#![no_main]

use libfuzzer_sys::fuzz_target;
use rizin_rs::wrapper::*;

fuzz_target!(|data: &[u8]| {
    let mut bin = Bin::new();
    let bf = bin.open_slice(data);
    let _ = bf.map(|mut x|x.dw());
});
