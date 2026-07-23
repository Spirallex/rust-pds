//! Running CPU-bound work without stalling the async runtime.
//!
//! The crate has a few genuinely expensive synchronous operations — argon2id
//! password hashing and key unwrapping, chiefly — which must not occupy an async
//! worker while they run. On a threaded tokio runtime the answer is
//! `spawn_blocking`. On `wasm32` there is no answer, because there is no thread
//! pool: a Cloudflare Workers isolate and a browser worker are both
//! single-threaded, and `spawn_blocking` there compiles but fails at runtime.
//!
//! [`run_blocking`] papers over exactly that difference and nothing else.
//!
//! # This is a real cost on wasm32, not a free abstraction
//!
//! Running inline means the isolate is occupied for the duration. At the default
//! 19 MiB / t=2 argon2id parameters that is tens of milliseconds per call, which
//! on Workers counts against CPU time and blocks every other task in the
//! isolate. The `lean-auth` feature (4 MiB) exists for constrained hosts and is
//! the right setting there — see [`crate::storage::crypto`] for the
//! key-compatibility caveat that comes with it.

/// Run `f`, off the async runtime where the platform has somewhere to put it.
///
/// Returns `None` if the work could not be completed — on a threaded runtime
/// that means the blocking task panicked or the runtime shut down. Callers map
/// that to their own error type; the signature avoids naming `JoinError` so the
/// wasm32 branch does not have to invent one.
///
/// The bounds are the union of what both platforms need: `Send + 'static` is
/// required by `spawn_blocking` and harmless on wasm32. The returned future is
/// `Send` on both, which callers inside `#[async_trait]` methods depend on —
/// `returned_future_is_send` in the tests below holds that.
#[cfg(not(target_arch = "wasm32"))]
pub async fn run_blocking<F, T>(f: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f).await.ok()
}

/// wasm32: no thread pool exists, so the closure runs inline on the caller.
///
/// Always `Some` — there is no task to fail independently of the caller.
#[cfg(target_arch = "wasm32")]
pub async fn run_blocking<F, T>(f: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    Some(f())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_the_closure_and_returns_its_value() {
        assert_eq!(run_blocking(|| 2 + 2).await, Some(4));
    }

    #[tokio::test]
    async fn moves_owned_data_in() {
        let owned = String::from("moved into the closure");
        assert_eq!(run_blocking(move || owned.len()).await, Some(22));
    }

    /// The returned future must be `Send` on every target.
    ///
    /// `crypto::store_key` and friends are called from `#[async_trait]` methods,
    /// whose futures are `Send`; if this regressed on the wasm32 branch the
    /// failure would appear as an inscrutable trait-bound error far from here.
    #[test]
    fn returned_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        assert_send(run_blocking(|| 1u8));
    }

    /// A panicking closure must surface as `None`, not unwind into the caller —
    /// otherwise one bad password hash would take down the request handler.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn a_panicking_closure_yields_none() {
        let result = run_blocking(|| -> i32 { panic!("boom") }).await;
        assert_eq!(result, None);
    }
}
