#![no_main]

use libfuzzer_sys::fuzz_target;
use rizin_rs::wrapper::*;
// use rizin_rs::RzBinDwarfLineInfoMask_RZ_BIN_DWARF_LINE_INFO_MASK_LINES_ALL;
//
// fuzz_target!(|input: LineInput| {
//     let mut abbrev = abbrev(&input.info.abbrev).unwrap();
//     let mut info = info(&input.info.info,false,&mut abbrev,None).unwrap();
//     let mut encoding = input.encoding;
//     let _ = line(&input.line,false,&mut encoding,RzBinDwarfLineInfoMask_RZ_BIN_DWARF_LINE_INFO_MASK_LINES_ALL,&mut info);
// });
