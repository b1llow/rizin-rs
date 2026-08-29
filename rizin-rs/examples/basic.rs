use rizin_rs::RzCore;

fn main() {
    let core = RzCore::new();
    core.config_set("analysis.arch", "x86").unwrap();
    core.config_set("analysis.bits", "64").unwrap();
    let arch = core.config_get("analysis.arch").unwrap();
    let bits = core.config_get("analysis.bits").unwrap();
    println!("Rizin analysis target: {arch}-{bits}");
}
