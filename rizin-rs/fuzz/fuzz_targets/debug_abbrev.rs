#![no_main]

use libfuzzer_sys::fuzz_target;
use rizin_rs::wrapper::DwarfAbbrev;

fuzz_target!(|input: &[u8]| {
    let _ = DwarfAbbrev::new(input);
});
