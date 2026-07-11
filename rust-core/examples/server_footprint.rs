//! Resting footprint of the embedded `hyper` server over the lean-auth floor.
//!
//! Run on Apple Silicon macOS (arm64 / libmalloc / 16 KB pages match iOS, so
//! `phys_footprint` here is a faithful proxy for the on-device workload; the
//! Network Extension just imposes a tighter ceiling on top):
//!
//!   cargo run -p stelyph-core --release \
//!     --features embedded-server,lean-auth --example server_footprint
//!
//! Reports `phys_footprint` (the exact metric iOS Jetsam meters) and peak RSS at:
//! baseline, after opening the store, after the server is bound + serving, and
//! after a real request round-trips through it. The delta from the store
//! checkpoint to "after request" is the marginal cost of adding an in-process
//! HTTP server to the host.

use std::net::SocketAddr;
use std::sync::Arc;

use stelyph_core::server::{bind, serve, ServerConfig};
use stelyph_core::storage::SqliteStore;

// `task_vm_info`, laid out (per <mach/task_info.h>) through `phys_footprint` —
// the exact field iOS Jetsam meters. The count we pass covers just these bytes;
// the kernel fills up to that and ignores trailing rev3+ ledger fields.
#[cfg(target_vendor = "apple")]
#[repr(C)]
#[derive(Default)]
struct TaskVmInfo {
    virtual_size: u64,
    region_count: i32,
    page_size: i32,
    resident_size: u64,
    resident_size_peak: u64,
    device: u64,
    device_peak: u64,
    internal: u64,
    internal_peak: u64,
    external: u64,
    external_peak: u64,
    reusable: u64,
    reusable_peak: u64,
    purgeable_volatile_pmap: u64,
    purgeable_volatile_resident: u64,
    purgeable_volatile_virtual: u64,
    compressed: u64,
    compressed_peak: u64,
    compressed_lifetime: u64,
    phys_footprint: u64,
}

#[cfg(target_vendor = "apple")]
fn phys_footprint_mb() -> f64 {
    use mach2::task::task_info;
    use mach2::task_info::{task_info_t, TASK_VM_INFO};
    use mach2::traps::mach_task_self;
    unsafe {
        let mut vm = TaskVmInfo::default();
        let mut count = (std::mem::size_of::<TaskVmInfo>() / std::mem::size_of::<i32>()) as u32;
        let kr = task_info(
            mach_task_self(),
            TASK_VM_INFO,
            &mut vm as *mut _ as task_info_t,
            &mut count,
        );
        if kr != 0 {
            return 0.0;
        }
        vm.phys_footprint as f64 / (1024.0 * 1024.0)
    }
}

/// phys_footprint is a mach (Apple) ledger; elsewhere report 0 and rely on
/// peak RSS. The example exists to be run on Apple hosts — this stub only
/// keeps it compiling in cross-platform CI.
#[cfg(not(target_vendor = "apple"))]
fn phys_footprint_mb() -> f64 {
    0.0
}

fn peak_rss_mb() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    usage.ru_maxrss as f64 / (1024.0 * 1024.0) // macOS reports bytes
}

fn report(label: &str) {
    println!(
        "{:<36} phys_footprint={:>6.1} MB   peak_rss={:>6.1} MB",
        label,
        phys_footprint_mb(),
        peak_rss_mb()
    );
}

/// Minimal raw HTTP GET so we exercise the real serve path (accept → parse →
/// store → respond), not just a bound-but-idle socket. Raw TCP keeps the example
/// off hyper's `client` feature.
async fn http_get(addr: SocketAddr, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: pds.test\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw);
    text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    report("baseline");

    let path = std::env::temp_dir()
        .join(format!("stelyph-srv-footprint-{}.db", std::process::id()))
        .to_string_lossy()
        .into_owned();
    let _ = std::fs::remove_file(&path);

    let store = Arc::new(SqliteStore::open(&path).await.expect("open store"));
    // Seed one account so resolveHandle returns a real row.
    store
        .insert_account("did:plc:footprint00000000", "alice.pds.test", None, "x")
        .await
        .expect("seed account");
    report("after open store + seed account");

    let listener = bind("127.0.0.1:0".parse().unwrap()).await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let srv_store = store.clone();
    let handle = tokio::spawn(async move {
        let _ = serve(
            listener,
            srv_store,
            ServerConfig {
                hostname: "pds.test".into(),
                open_registration: false,
                jwt_secret: b"footprint-example-jwt-secret".to_vec(),
                key_passphrase: b"footprint-example-passphrase".to_vec(),
                appview_did: "did:web:api.bsky.app".into(),
            },
            None,
        )
        .await;
    });
    report("after server bound + serving");

    let describe = http_get(addr, "/xrpc/com.atproto.server.describeServer").await;
    let resolved = http_get(
        addr,
        "/xrpc/com.atproto.identity.resolveHandle?handle=alice.pds.test",
    )
    .await;
    report("after request round-trip");

    handle.abort();
    println!("\nserver listened on http://{addr}");
    println!("describeServer  -> {describe}");
    println!("resolveHandle   -> {resolved}");
    let _ = std::fs::remove_file(&path);
}
