# dupscan

A multithreaded duplicate-file finder written in Rust. Zero dependencies — standard library only.

## How it works

Hashing every byte of every file is wasteful, so dupscan filters in cheap-to-expensive phases. Only files that survive all four phases are reported:

1. **Group by file size** — free, comes from directory metadata. Different size ⇒ can't be duplicates.
2. **Hash the first 8 KiB** — one small read per file (FNV-1a, hand-rolled).
3. **Hash the whole file** — the expensive step, parallelized across N worker threads via channels.
4. **Byte-compare survivors** — the definitive check, so a hash collision can never cause a false report.

It also handles the edge cases correctly:

- **Symlinks are never followed** (uses `symlink_metadata`), so symlinked trees can't cause infinite recursion or double counting.
- **Hardlinks are deduplicated** by `(device, inode)` — two hardlinks are the same file, not wasted space.
- Files stream in 64 KiB chunks, so a 10 GiB file never blows up memory.

## Build

```sh
cargo build --release
```

## Usage

```sh
dupscan <DIR> [--min-size BYTES] [--threads N] [--json]
```

Example:

```sh
$ dupscan ~/Downloads
duplicate set #1 — 3 files, 50000 bytes each:
    /home/user/Downloads/a.bin
    /home/user/Downloads/b.bin
    /home/user/Downloads/sub/c.bin

scanned 6 files in 0.00s → 1 duplicate set, 3 duplicate files, 100000 wasted bytes
```

## Design notes

- **Thread pool**: a fixed set of workers pulls paths off a shared `mpsc` job channel; results return on a second channel. The receiver is shared via `Arc<Mutex<..>>` because `std`'s `Receiver` isn't `Sync`.
- **Fail-fast arg parsing**: bad flags exit with code 2 and a usage message; runtime errors exit 1.
- **Tests**: `cargo test` covers hash equality/inequality, byte-compare exactness, and partial-hash limits.

## Key Rust concepts used

Ownership & borrowing, `Result`/`Option` error handling, closures, channels (`mpsc`), `Arc`/`Mutex` for shared state, wrapping arithmetic, unit tests with `#[cfg(test)]`.
