/* M13 NODE - BUILD ORCHESTRATOR
 * Node uses UDP sockets (no AF_XDP, no BPF).
 * Build step: generate kernel bindings for ethtool/ifreq.
 */
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(match env::var("OUT_DIR") {
        Ok(v) => v,
        Err(_) => { eprintln!("[M13-NODE-BUILD] OUT_DIR not set"); std::process::exit(1); }
    });

    // Generate kernel bindings (ethtool ring params, ifreq)
    let bindings = bindgen::Builder::default()
        .header_contents("wrapper.h", "#include <linux/ethtool.h>\n#include <linux/sockios.h>\n#include <linux/if.h>")
        .allowlist_type("ethtool_ringparam")
        .allowlist_type("ifreq")
        .allowlist_var("SIOCETHTOOL")
        .allowlist_var("ETHTOOL_GRINGPARAM")
        .derive_default(true)
        .generate();
    let bindings = match bindings {
        Ok(b) => b,
        Err(_) => { eprintln!("[M13-NODE-BUILD] Unable to generate bindings"); std::process::exit(1); }
    };

    if bindings.write_to_file(out_dir.join("bindings.rs")).is_err() {
        eprintln!("[M13-NODE-BUILD] Failed to write bindings");
        std::process::exit(1);
    }
}
