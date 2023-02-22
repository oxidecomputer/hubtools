use anyhow::{bail, Context, Result};

use std::path::Path;
use std::process::Command;

fn objcopy_translate_format(
    in_format: &str,
    src: &Path,
    out_format: &str,
    dest: &Path,
) -> Result<()> {
    let mut cmd = Command::new("arm-none-eabi-objcopy");
    cmd.arg("-I")
        .arg(in_format)
        .arg("-O")
        .arg(out_format)
        .arg("--gap-fill")
        .arg("0xFF")
        .arg(src)
        .arg(dest);

    let status = cmd
        .status()
        .context(format!("failed to objcopy ({:?})", cmd))?;

    if !status.success() {
        bail!("objcopy failed, see output for details");
    }
    Ok(())
}

/// Convert SREC to other formats for convenience.
pub fn translate_srec_to_other_formats(
    dist_dir: &Path,
    name: &str,
) -> Result<()> {
    let src = dist_dir.join(format!("{}.srec", name));
    for (out_type, ext) in [
        ("elf32-littlearm", "elf"),
        ("ihex", "ihex"),
        ("binary", "bin"),
    ] {
        objcopy_translate_format(
            "srec",
            &src,
            out_type,
            &dist_dir.join(format!("{}.{}", name, ext)),
        )?;
    }
    Ok(())
}
