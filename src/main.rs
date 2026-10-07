//! dupscan — a multithreaded duplicate-file finder.
//!
//! Finding duplicates by hashing *every* byte of *every* file is wasteful,
//! so dupscan filters in cheap-to-expensive phases:
//!
//!   1. Group by file size        (free — comes from directory metadata)
//!   2. Hash the first 8 KiB     (cheap — one small read per file)
//!   3. Hash the whole file      (expensive — done in parallel on N threads)
//!   4. Byte-compare survivors   (confirms true duplicates; immune to hash collisions)
//!
//! Only files that survive all four phases are reported as duplicates.
//! Zero dependencies — everything here is Rust's standard library.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Instant;

// ---------------------------------------------------------------------------
// FNV-1a 64-bit hash, implemented by hand (no hashing crate needed).
// Good enough as a fast non-cryptographic fingerprint; phase 4 below
// byte-compares anyway, so a collision can never cause a false report.
// ---------------------------------------------------------------------------
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn fnv1a_chunk(data: &[u8], mut hash: u64) -> u64 {
    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME); // wrapping: overflow is part of the algorithm
    }
    hash
}

/// Hash up to `max_bytes` of a file (None = the whole file), streaming in
/// 64 KiB chunks so a 10 GiB file never blows up memory.
fn hash_file(path: &Path, max_bytes: Option<u64>) -> io::Result<u64> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut hash = FNV_OFFSET_BASIS;
    let mut buf = [0u8; 64 * 1024];
    let mut remaining = max_bytes.unwrap_or(u64::MAX);

    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = reader.read(&mut buf[..want])?;
        if n == 0 {
            break; // EOF
        }
        hash = fnv1a_chunk(&buf[..n], hash);
        remaining -= n as u64;
    }
    Ok(hash)
}

/// Definitive check: are these two files byte-identical?
fn files_identical(a: &Path, b: &Path) -> io::Result<bool> {
    let mut fa = BufReader::with_capacity(64 * 1024, File::open(a)?);
    let mut fb = BufReader::with_capacity(64 * 1024, File::open(b)?);
    let mut ba = [0u8; 64 * 1024];
    let mut bb = [0u8; 64 * 1024];
    loop {
        let na = fa.read(&mut ba)?;
        let nb = fb.read(&mut bb)?;
        if na != nb || ba[..na] != bb[..nb] {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true); // both hit EOF together, all chunks matched
        }
    }
}

// ---------------------------------------------------------------------------
// Directory walk. Uses symlink_metadata (never follows symlinks) and skips
// them, so a symlinked tree can't cause infinite recursion or double counting.
// ---------------------------------------------------------------------------
fn walk(dir: &Path, out: &mut Vec<(PathBuf, u64)>, min_size: u64) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            walk(&path, out, min_size)?;
        } else if meta.is_file() && meta.len() >= min_size {
            out.push((path, meta.len()));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Parallel full-file hashing. A fixed pool of worker threads pulls paths off
// a shared job channel; results come back on a second channel. The receiver
// is wrapped in Arc<Mutex<..>> because std's mpsc Receiver is not shareable
// between threads directly.
// ---------------------------------------------------------------------------
fn hash_parallel(paths: Vec<PathBuf>, threads: usize) -> Vec<(PathBuf, u64)> {
    let (job_tx, job_rx) = mpsc::channel::<PathBuf>();
    let (res_tx, res_rx) = mpsc::channel::<(PathBuf, u64)>();
    let job_rx = Arc::new(Mutex::new(job_rx));

    let mut workers = Vec::with_capacity(threads);
    for _ in 0..threads.max(1) {
        let job_rx = Arc::clone(&job_rx);
        let res_tx = res_tx.clone();
        workers.push(thread::spawn(move || loop {
            let path = job_rx.lock().expect("job channel poisoned").recv();
            match path {
                Ok(p) => match hash_file(&p, None) {
                    Ok(h) => {
                        let _ = res_tx.send((p, h));
                    }
                    Err(e) => eprintln!("warning: cannot hash {}: {e}", p.display()),
                },
                Err(_) => break, // job channel closed: no more work
            }
        }));
    }
    drop(res_tx); // workers hold the remaining clones; channel closes when they exit

    for p in paths {
        let _ = job_tx.send(p);
    }
    drop(job_tx); // closing this is what lets workers break out of recv()

    let mut out = Vec::new();
    for r in res_rx {
        out.push(r);
    }
    for w in workers {
        let _ = w.join();
    }
    out
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
struct Args {
    dir: PathBuf,
    min_size: u64,
    threads: usize,
    json: bool,
}

fn print_usage() {
    eprintln!("usage: dupscan <DIR> [--min-size BYTES] [--threads N] [--json]");
}

fn parse_args() -> Result<Args, String> {
    let mut it = env::args().skip(1).peekable();
    let mut args = Args {
        dir: PathBuf::new(),
        min_size: 1,
        threads: thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
        json: false,
    };
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix("--min-size=") {
            args.min_size = v.parse().map_err(|_| "bad --min-size value".to_string())?;
        } else if a == "--min-size" {
            let v = it.next().ok_or("--min-size needs a value".to_string())?;
            args.min_size = v.parse().map_err(|_| "bad --min-size value".to_string())?;
        } else if let Some(v) = a.strip_prefix("--threads=") {
            args.threads = v.parse().map_err(|_| "bad --threads value".to_string())?;
        } else if a == "--threads" {
            let v = it.next().ok_or("--threads needs a value".to_string())?;
            args.threads = v.parse().map_err(|_| "bad --threads value".to_string())?;
        } else if a == "--json" {
            args.json = true;
        } else if a.starts_with("--") {
            return Err(format!("unknown flag: {a}"));
        } else if args.dir.as_os_str().is_empty() {
            args.dir = PathBuf::from(a);
        } else {
            return Err("only one directory argument is supported".to_string());
        }
    }
    if args.dir.as_os_str().is_empty() {
        return Err("missing <DIR> argument".to_string());
    }
    Ok(args)
}

fn main() {
    let args = parse_args().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        print_usage();
        std::process::exit(2);
    });
    if let Err(e) = run(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: &Args) -> io::Result<()> {
    let start = Instant::now();

    // Phase 0: walk + hardlink dedup. Two paths with the same (dev, ino) are
    // the same file (hardlinks), not duplicates of each other.
    let mut found: Vec<(PathBuf, u64)> = Vec::new();
    walk(&args.dir, &mut found, args.min_size)?;
    let mut seen_inodes: HashSet<(u64, u64)> = HashSet::new();
    let mut files: Vec<(PathBuf, u64)> = Vec::new();
    for (p, size) in found {
        if let Ok(meta) = fs::symlink_metadata(&p) {
            if seen_inodes.insert((meta.dev(), meta.ino())) {
                files.push((p, size));
            }
        }
    }
    let scanned = files.len();

    // Phase 1: group by size. Different size => cannot be duplicates.
    let mut by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    for (p, size) in files {
        by_size.entry(size).or_default().push(p);
    }

    // Phase 2: within each size-group, hash the first 8 KiB.
    let mut candidates: Vec<PathBuf> = Vec::new();
    for (_size, group) in by_size.iter().filter(|(_, g)| g.len() > 1) {
        let mut by_partial: HashMap<u64, Vec<PathBuf>> = HashMap::new();
        for p in group {
            match hash_file(p, Some(8 * 1024)) {
                Ok(h) => by_partial.entry(h).or_default().push(p.clone()),
                Err(e) => eprintln!("warning: cannot read {}: {e}", p.display()),
            }
        }
        for (_h, g) in by_partial.into_iter().filter(|(_, g)| g.len() > 1) {
            candidates.extend(g);
        }
    }

    // Phase 3: full-file hash of the survivors, in parallel.
    let hashed = hash_parallel(candidates, args.threads);
    let mut by_full: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    for (p, h) in hashed {
        by_full.entry(h).or_default().push(p);
    }

    // Phase 4: byte-compare to confirm. Hash collisions can never slip through.
    let mut groups: Vec<Vec<PathBuf>> = Vec::new();
    for (_h, group) in by_full.into_iter().filter(|(_, g)| g.len() > 1) {
        let mut confirmed: Vec<Vec<PathBuf>> = Vec::new();
        'outer: for p in group {
            for set in confirmed.iter_mut() {
                if files_identical(&set[0], &p).unwrap_or(false) {
                    set.push(p.clone());
                    continue 'outer;
                }
            }
            confirmed.push(vec![p.clone()]);
        }
        groups.extend(confirmed.into_iter().filter(|g| g.len() > 1));
    }
    groups.sort_by_key(|g| std::cmp::Reverse(group_size(g)));

    let dup_files: usize = groups.iter().map(|g| g.len()).sum();
    let wasted: u64 = groups
        .iter()
        .map(|g| group_size(g) * (g.len() as u64 - 1))
        .sum();
    let elapsed = start.elapsed();

    if args.json {
        print_json(&groups, scanned, dup_files, wasted);
    } else {
        print_human(&groups, scanned, dup_files, wasted, elapsed);
    }
    Ok(())
}

fn group_size(group: &[PathBuf]) -> u64 {
    group
        .first()
        .and_then(|p| fs::metadata(p).ok())
        .map(|m| m.len())
        .unwrap_or(0)
}

fn print_human(
    groups: &[Vec<PathBuf>],
    scanned: usize,
    dup_files: usize,
    wasted: u64,
    elapsed: std::time::Duration,
) {
    let out = io::stdout();
    let mut o = io::BufWriter::new(out.lock());
    for (i, g) in groups.iter().enumerate() {
        let _ = writeln!(
            o,
            "duplicate set #{} — {} files, {} bytes each:",
            i + 1,
            g.len(),
            group_size(g)
        );
        for p in g {
            let _ = writeln!(o, "    {}", p.display());
        }
    }
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "scanned {scanned} files in {:.2}s → {} duplicate sets, {dup_files} duplicate files, {wasted} wasted bytes",
        elapsed.as_secs_f64(),
        groups.len(),
    );
}

fn print_json(groups: &[Vec<PathBuf>], scanned: usize, dup_files: usize, wasted: u64) {
    // Hand-rolled JSON: the schema is tiny and this keeps zero dependencies.
    let out = io::stdout();
    let mut o = io::BufWriter::new(out.lock());
    let _ = writeln!(o, "{{");
    let _ = writeln!(o, "  \"scanned_files\": {scanned},");
    let _ = writeln!(o, "  \"duplicate_sets\": {},", groups.len());
    let _ = writeln!(o, "  \"duplicate_files\": {dup_files},");
    let _ = writeln!(o, "  \"wasted_bytes\": {wasted},");
    let _ = writeln!(o, "  \"groups\": [");
    for (i, g) in groups.iter().enumerate() {
        let _ = writeln!(o, "    [");
        for (j, p) in g.iter().enumerate() {
            let comma = if j + 1 == g.len() { "" } else { "," };
            let _ = writeln!(
                o,
                "      \"{}\"{comma}",
                p.display().to_string().replace('"', "\\\"")
            );
        }
        let comma = if i + 1 == groups.len() { "" } else { "," };
        let _ = writeln!(o, "    ]{comma}");
    }
    let _ = writeln!(o, "  ]");
    let _ = writeln!(o, "}}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_file(name: &str, content: &[u8]) -> PathBuf {
        let dir = env::temp_dir().join(format!("dupscan-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn identical_files_hash_equal() {
        let a = tmp_file("a.bin", b"hello world");
        let b = tmp_file("b.bin", b"hello world");
        assert_eq!(hash_file(&a, None).unwrap(), hash_file(&b, None).unwrap());
    }

    #[test]
    fn different_files_hash_differ() {
        let a = tmp_file("c.bin", b"hello world");
        let b = tmp_file("d.bin", b"hello worle");
        assert_ne!(hash_file(&a, None).unwrap(), hash_file(&b, None).unwrap());
    }

    #[test]
    fn byte_compare_is_exact() {
        let a = tmp_file("e.bin", b"abc");
        let b = tmp_file("f.bin", b"abc");
        let c = tmp_file("g.bin", b"abd");
        assert!(files_identical(&a, &b).unwrap());
        assert!(!files_identical(&a, &c).unwrap());
    }

    #[test]
    fn partial_hash_respects_limit() {
        // Same 8 KiB prefix, different tails => partial hashes equal, full differ.
        let x = vec![0u8; 16 * 1024];
        let mut y = vec![0u8; 16 * 1024];
        y[12 * 1024] = 1;
        let a = tmp_file("h.bin", &x);
        let b = tmp_file("i.bin", &y);
        assert_eq!(
            hash_file(&a, Some(8 * 1024)).unwrap(),
            hash_file(&b, Some(8 * 1024)).unwrap()
        );
        assert_ne!(hash_file(&a, None).unwrap(), hash_file(&b, None).unwrap());
    }
}
