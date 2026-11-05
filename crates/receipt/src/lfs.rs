//! Git LFS pointer files (D96). A pointer is a small text file committed in place of a large one:
//!
//! ```text
//! version https://git-lfs.github.com/spec/v1
//! oid sha256:<64 hex>
//! size <bytes>
//! ```
//!
//! Pure functions on bytes; nothing here touches git or the network.

use crate::statement::LfsFile;

const VERSION_LINE: &str = "version https://git-lfs.github.com/spec/v1";

/// A pointer is never this big; anything larger is a real file, whatever it starts with.
pub const MAX_LFS_POINTER_BYTES: usize = 1024;

/// True when `blob` starts the way an LFS pointer does. Cheap: for choosing what to look at.
pub fn looks_like_lfs_pointer(blob: &[u8]) -> bool {
    blob.len() <= MAX_LFS_POINTER_BYTES && blob.starts_with(VERSION_LINE.as_bytes())
}

/// Read `blob` as an LFS pointer for the file at `path`: the object id and size it names.
/// `None` when it is not one, including a pointer that does not name both exactly.
pub fn lfs_pointer(path: &str, blob: &[u8]) -> Option<LfsFile> {
    if !looks_like_lfs_pointer(blob) {
        return None;
    }
    let text = std::str::from_utf8(blob).ok()?;
    let mut lines = text.lines();
    if lines.next()? != VERSION_LINE {
        return None;
    }
    let (mut oid, mut size) = (None, None);
    for line in lines {
        let (key, value) = line.split_once(' ')?;
        match key {
            "oid" if oid.is_none() => {
                let hex = value.strip_prefix("sha256:")?;
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                    return None;
                }
                oid = Some(hex.to_string());
            }
            "size" if size.is_none() => size = Some(value.parse::<u64>().ok()?),
            // Extensions and unknown keys are allowed by the format; a repeated oid or size is not.
            "oid" | "size" => return None,
            _ => {}
        }
    }
    Some(LfsFile { path: path.to_string(), oid: oid?, size: size? })
}

/// True when a `.gitattributes` file sends some files through the LFS filter.
pub fn attributes_use_lfs(attributes: &[u8]) -> bool {
    String::from_utf8_lossy(attributes)
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .any(|l| l.split_whitespace().skip(1).any(|a| a == "filter=lfs"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OID: &str = "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393";

    fn pointer(oid: &str, size: &str) -> Vec<u8> {
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize {size}\n").into_bytes()
    }

    #[test]
    fn a_pointer_names_its_object_and_size() {
        let f = lfs_pointer("assets/big.bin", &pointer(OID, "12345")).unwrap();
        assert_eq!((f.path.as_str(), f.oid.as_str(), f.size), ("assets/big.bin", OID, 12345));
    }

    #[test]
    fn anything_else_is_not_a_pointer() {
        assert!(lfs_pointer("a", b"hello\n").is_none());
        assert!(lfs_pointer("a", &pointer("abc", "1")).is_none(), "a short object id");
        assert!(lfs_pointer("a", &pointer(&OID.to_uppercase(), "1")).is_none(), "upper-case hex");
        assert!(lfs_pointer("a", &pointer(OID, "many")).is_none(), "a size that is not a number");
        assert!(lfs_pointer("a", b"version https://git-lfs.github.com/spec/v1\nsize 3\n").is_none(), "no object id");
        let twice = [pointer(OID, "1"), b"size 2\n".to_vec()].concat();
        assert!(lfs_pointer("a", &twice).is_none(), "two sizes");
        let big = [pointer(OID, "1"), vec![b'x'; MAX_LFS_POINTER_BYTES]].concat();
        assert!(lfs_pointer("a", &big).is_none(), "a real file that starts like a pointer");
    }

    #[test]
    fn extension_lines_are_allowed() {
        let mut p = b"version https://git-lfs.github.com/spec/v1\next-0-foo sha256:00\n".to_vec();
        p.extend(format!("oid sha256:{OID}\nsize 9\n").into_bytes());
        assert_eq!(lfs_pointer("a", &p).unwrap().size, 9);
    }

    #[test]
    fn attributes_that_use_lfs_are_recognised() {
        assert!(attributes_use_lfs(b"*.bin filter=lfs diff=lfs merge=lfs -text\n"));
        assert!(attributes_use_lfs(b"# comment\n\n  assets/** filter=lfs\n"));
        assert!(!attributes_use_lfs(b"# *.bin filter=lfs\n*.txt text eol=lf\n"));
        assert!(!attributes_use_lfs(b"*.bin filter=other\n"));
        assert!(!attributes_use_lfs(b"filter=lfs\n"), "the first word is the pattern");
    }
}
