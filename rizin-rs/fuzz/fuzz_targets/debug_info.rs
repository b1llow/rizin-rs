#![no_main]

use libfuzzer_sys::fuzz_target;
// use rizin_rs::wrapper::*;
//
// fuzz_target!(|input: InfoInput| {
//     let mut abbrev = abbrev(&input.abbrev).unwrap();
//     let _ = info(&input.info,false,&mut abbrev,None);
// });
