# pesieve-rs
Rust bindings for the [PE-sieve](https://github.com/hasherezade/pe-sieve/) tool developed by [hasherezade](https://github.com/hasherezade).

## API

Exposes the following wrappers for [PE-sieve API](https://github.com/hasherezade/pe-sieve/wiki/5.-API):

```rust
fn pesieve_help()
fn pesieve_scan(params: Params) -> Report 
fn pesieve_scan_ex(params: Params, rtype: ReportType, json_buf_size: usize) -> (Report, String, usize)
```

## Build

Requires the PESieve DLL file of a supported version to be present in the project directory or in a path pointed by the `PESIEVE_DIR` environment variable.

To add the project as a dependency of your project and build it use the following cargo commands:

```
cargo add --git https://github.com/leandrofroes/pesieve-rs.git
cargo build
```

## Example

```
cargo run --example scan_proc
```