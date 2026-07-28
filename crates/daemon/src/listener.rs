//! Loopback passthrough proxy for blocked domains.
//!
//! A domain block points its domains at a sink IP in `/etc/hosts`, so the
//! browser's connection dies locally and the daemon never hears about it.
//! Pointing the sink at `127.0.0.1` and listening there changes what "blocked"
//! means: the browser connects to us instead of to a dark address, tells us
//! the hostname it wanted (in the HTTP `Host:` header or the TLS SNI
//! extension), and we decide what to do with the connection.
//!
//! This module is the mechanism for that proxy. It binds the two ports, reads
//! the hostname, and manages the sockets' lifetime; nothing here consults or
//! mutates daemon state. `enforce::sync` owns the lifecycle and the sink-IP
//! decision that turns this on.
//!
//! # This stage: refuse-only
//!
//! For now the proxy does exactly one thing with a connection: it refuses it.
//! On `:80` it writes the static [`BLOCK_RESPONSE`] (a `403`) and closes; on
//! `:443` it closes without sending a byte. The hostname is read — the parsers
//! below are the audited, fuzzed code the next stage needs — but this stage
//! does nothing with it beyond an optional `debug!` line. The observable
//! behaviour is therefore identical to the historical `0.0.0.0` sink: a
//! blocked domain does not load. What has changed is only *where* the
//! connection dies — on our loopback socket rather than at an unrouteable
//! address — which is the seam the next commit needs.
//!
//! **Forwarding is deliberately absent.** The whole point of a passthrough
//! proxy — reading the hostname and then splicing the connection on to the
//! real site while a break is active — arrives in the next commit. There is no
//! `copy_bidirectional`, no upstream connect, and no DNS resolution here yet.
//!
//! # Failure policy
//!
//! A failed bind is NOT an error to propagate. Ports 80 and 443 are commonly
//! taken on a developer's machine, which is exactly the population that runs
//! this, so losing the race is an ordinary outcome. It mirrors the nftables
//! half of `enforce::apply`, which reports `Ok(false)` rather than `Err`:
//! enforcement never depends on the listener (a sink of `127.0.0.1` with
//! nothing listening still refuses the connection), so every failure path here
//! degrades the proxy alone. The caller inspects [`ProxyListener::fully_bound`]
//! and decides.
//!
//! Binding is all-or-nothing: a run that gets `:80` but not `:443` keeps
//! neither. Half of it is worth nothing — the caller's answer to a degraded
//! proxy is to point the sink at `0.0.0.0`, so no connection can arrive on the
//! port that did bind — and a root process squatting `:80` to hear traffic
//! that is now impossible is strictly worse than not having bound it.
//!
//! # Security
//!
//! These parsers run AS ROOT against bytes from any local process, so the
//! rules they are written under are worth stating:
//!
//! - No panics on any input. Every read goes through [`Cursor`], which
//!   bounds-checks and returns `None` rather than indexing; there is no
//!   `unwrap`/`expect` and no arithmetic that could wrap into an index.
//! - No allocation sized by the wire. The read buffer is a fixed
//!   [`MAX_READ`]; a length field from the network is only ever used to
//!   *check* or *slice*, never to reserve.
//! - Bounded reads with a timeout, so a client that connects and says nothing
//!   cannot hold a task.
//! - One static response on :80, no body parsing, and on :443 not a single
//!   byte is sent — no certificate, so no "your connection is not private"
//!   dialogue and no trust decision pushed onto the user.
//!
//! ## Open question: should this run with lower privilege?
//!
//! Recorded rather than assumed, because the answer is a judgement and not an
//! obvious one. Binding a port below 1024 needs privilege, so the bind itself
//! has to happen here; what follows it — parsing untrusted bytes as root — is
//! the largest hostile-input surface in the daemon. Full privilege separation
//! (fork a helper, drop to `nobody`, pass hostnames back over a socketpair)
//! was judged disproportionate *for now*, for four reasons:
//!
//! 1. The surface is two pure functions over a fixed-size buffer. No
//!    recursion, no subprocess, no filesystem, no state access, no allocation
//!    driven by the wire, no third-party parser — a TLS crate was deliberately
//!    not added. It is ~150 lines that one person can read in full, and the
//!    tests below fuzz both parsers against mutated ClientHellos and request
//!    heads — every truncation, every 16-bit field replaced with 0, 0xFFFF or
//!    a length just past the end, a repeated `server_name`, and thousands of
//!    random pokes — asserting not only that nothing panics but that any
//!    hostname returned is a run of bytes that was in the input.
//! 2. It is gated by a setting (`Settings::instant_breaks`) and only ever
//!    binds while a block is active, so on an idle or opted-out install the
//!    surface does not exist at all.
//! 3. Only `127.0.0.1` is bound, so the reachable population is local
//!    processes — which on a single-user desktop already run as the user whose
//!    browser this is watching. Someone who can connect here can already
//!    ptrace that browser.
//! 4. A helper process is not free. It adds a second privilege domain to
//!    supervise and an IPC channel that itself parses untrusted input, trading
//!    a small audited surface for a larger unaudited one.
//!
//! The trade-off flips the moment this grows a real HTTP server, a body
//! parser, a TLS handshake, or any allocation sized from the wire. Keeping the
//! parsers pure and dependency-free is what keeps reason (1) true, and is the
//! cheaper half of the same defence. A middle option exists if the balance
//! shifts before then: run the daemon with `CAP_NET_BIND_SERVICE` and drop the
//! rest, which buys most of the isolation without a second process.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Plain-HTTP port. A blocked site served over HTTP announces itself in the
/// request head.
const HTTP_PORT: u16 = 80;
/// HTTPS port. We never complete the handshake — the ClientHello alone carries
/// the hostname.
const HTTPS_PORT: u16 = 443;

/// Hard ceiling on what one connection may make us read, and therefore the
/// size of the only buffer we allocate per connection. A ClientHello is
/// typically 1–2 KB (more with post-quantum key shares), and an HTTP request
/// head that has not produced a `Host:` in 8 KB is not going to.
const MAX_READ: usize = 8 * 1024;

/// Wall-clock bound on reading the hostname out of one connection, covering
/// every read together rather than each in turn: a client dribbling one byte
/// at a time must not be able to renew its own deadline forever.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Bound on writing the static :80 response. A peer that connects, sends a
/// request and then refuses to read must not hold the task either.
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Ceiling on connection tasks in flight, shared by both ports.
///
/// Without one, every accepted connection is a detached task holding a file
/// descriptor for up to `READ_TIMEOUT + WRITE_TIMEOUT`, and a local process can
/// open them far faster than that — thousands in a fraction of a second. The
/// descriptor table is the daemon's, not the listener's: run it dry and
/// `hosts::apply_block` cannot open `/etc/hosts`, `enforce::sync` starts
/// returning `Err`, and the block stops being re-applied or extended. The proxy
/// must not be able to stall enforcement, so it gets a budget it cannot exceed.
///
/// A few hundred, not a few thousand, and deliberately below the 1024 soft
/// `LimitNOFILE` a daemon started without our unit file would get: even at the
/// cap, everything else the daemon needs a descriptor for still has room. It is
/// also far above any legitimate load — a page load against a blocked domain
/// opens a handful of connections, a fan-out across many blocked subdomains
/// tens.
const MAX_CONNECTIONS: usize = 256;

/// Back-off after a failing `accept`, so a persistent error (EMFILE, most
/// likely) cannot spin the runtime.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Floor on the interval between log lines about a condition the peer controls.
///
/// Both conditions the accept loop can shout about — a refused connection, a
/// failing `accept` — are driven by whoever is hammering the port, so a line
/// per event hands them the journal: the back-off alone would emit ten warnings
/// a second for as long as the pressure lasts. One line per interval carrying
/// the count since the last one says the same thing and cannot become the
/// denial of service it is reporting.
const LOG_INTERVAL: Duration = Duration::from_secs(60);

/// The entire :80 response. A fixed byte string, not a rendered page and not a
/// server: no request body is read, no header of the request influences it,
/// and the connection closes immediately afterwards. (The real block page, if
/// it ever ships, is a later and separate decision.)
///
/// Status is `403 Forbidden`, never `200 OK`: a `200` semantically asserts
/// "this IS the content of the requested URL", which a browser is entitled to
/// cache and, worse, to treat as the page succeeding. `403` says the request
/// was refused. `Cache-Control: no-store` forbids caching outright, so the
/// instant a break lifts the block the next request goes back to the network
/// rather than being served this refusal from disk.
///
/// `Connection: close` states what we are about to do anyway, so the browser
/// does not wait for a second response on a socket that is already going away.
const BLOCK_RESPONSE: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\
    Content-Type: text/plain; charset=utf-8\r\n\
    Content-Length: 22\r\n\
    Cache-Control: no-store\r\n\
    Connection: close\r\n\
    \r\n\
    Blocked by GrepFocus.\n";

/// Longest hostname we will accept, from the DNS name limit. A cheap length
/// check before anything is allocated.
const MAX_HOSTNAME: usize = 253;

/// What a connection on this socket is expected to be speaking. Chosen by the
/// port we accepted on, never sniffed from the bytes: a plaintext parser must
/// not be reachable from a TLS port or the other way round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    /// Plain HTTP/1.x — parse the `Host:` header, answer with
    /// [`BLOCK_RESPONSE`].
    Http,
    /// TLS — parse the ClientHello's SNI extension and send nothing at all.
    Tls,
}

/// Every port the proxy wants, and what it expects to hear on each. Both or
/// neither — see the failure policy above.
const PORTS: [(u16, Probe); 2] = [(HTTP_PORT, Probe::Http), (HTTPS_PORT, Probe::Tls)];

/// The pair of loopback sockets, and their lifetime.
///
/// Bound while a domain block is active, released when none is. Holding the
/// accept tasks IS holding the sockets: an accept task owns its `TcpListener`,
/// so the port is freed when the runtime drops that task's future — which
/// happens after an [`abort`](JoinHandle::abort) and NOT merely because this
/// value went away. Dropping a tokio `JoinHandle` detaches the task; it does
/// not stop it. That is why there is both a [`Drop`] impl and a
/// [`release`](ProxyListener::release), and why neither is decoration.
pub struct ProxyListener {
    /// One accept task per bound port — so either none, or one per entry in
    /// [`PORTS`]. Per-CONNECTION tasks are deliberately not tracked: each is
    /// bounded by [`READ_TIMEOUT`] and by a permit from a fixed budget
    /// ([`MAX_CONNECTIONS`]), so a registry of them would be a list that grows
    /// with traffic and buys nothing.
    tasks: Vec<JoinHandle<()>>,
    /// Whether BOTH ports were bound. The degraded state the caller inspects,
    /// exactly as `enforce::apply` returns whether the nft half installed.
    fully_bound: bool,
}

impl ProxyListener {
    /// Bind both loopback ports and start accepting.
    ///
    /// Never fails: a port that could not be bound (already in use, or EACCES
    /// when not privileged) is logged and skipped, and the result reports the
    /// shortfall through [`ProxyListener::fully_bound`]. Binding neither port
    /// is a legitimate outcome — the proxy is off, enforcement is untouched.
    ///
    /// All-or-nothing: unless every port bound, this holds no socket at all and
    /// no accept task exists to hold one.
    pub async fn start() -> Self {
        let Some(bound) = bind_all(&PORTS).await else {
            return Self {
                tasks: Vec::new(),
                fully_bound: false,
            };
        };
        info!("loopback proxy listening on 127.0.0.1:80 and :443");
        Self::serve(bound)
    }

    /// Start one accept task per already-bound listener, all drawing on one
    /// shared connection budget so the cap is on the daemon and not on each
    /// port in turn.
    fn serve(listeners: Vec<(TcpListener, Probe)>) -> Self {
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let fully_bound = listeners.len() == PORTS.len();
        let tasks = listeners
            .into_iter()
            .map(|(listener, probe)| spawn_accept(listener, probe, permits.clone()))
            .collect();
        Self { tasks, fully_bound }
    }

    /// Whether both ports are bound. `false` means the proxy is degraded (or
    /// absent) — never that enforcement is.
    pub fn fully_bound(&self) -> bool {
        self.fully_bound
    }

    /// Release the ports, and do not return until they are actually free.
    ///
    /// `abort` only *requests* cancellation: it returns before the runtime has
    /// dropped the task's future, and therefore before the `TcpListener` that
    /// future owns is closed. The gap is short — a couple of milliseconds — but
    /// it is long enough that a caller releasing and re-binding within the same
    /// tick (one block ending as another starts) got `EADDRINUSE` every single
    /// time, logged "proxy degraded", and then stayed degraded until the next
    /// natural transition. Awaiting the aborted handles closes it: when this
    /// returns, the ports are bindable.
    ///
    /// In-flight connection tasks are left to finish, since they are already
    /// timeout-bounded, hold nothing but their own permit, and are not what the
    /// port is waiting on.
    pub async fn release(mut self) {
        // Taken, so the `Drop` below finds an empty vec and does not repeat the
        // aborts. The value is still dropped at the end of this function.
        for task in std::mem::take(&mut self.tasks) {
            task.abort();
            // `Err(Cancelled)` is the expected outcome and means the future has
            // been dropped — which is exactly the event we are waiting for.
            let _ = task.await;
        }
        debug!("loopback proxy released its ports");
    }
}

/// Best-effort teardown for every path that does not go through
/// [`release`](ProxyListener::release) — a panic, an early return, a future
/// cancelled mid-`sync`.
///
/// The two coexist because `drop` cannot await. This stops the accept tasks but
/// cannot wait for the runtime to drop them, so the ports come free a moment
/// later rather than immediately; `release` is the ordered path that also
/// guarantees the *when*. Without this impl, dropping a `ProxyListener` would
/// abort nothing at all: the detached accept tasks would keep both privileged
/// ports for the life of the process, still answering requests.
impl Drop for ProxyListener {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Bind every port in `ports`, or none of them.
///
/// The `?` is the whole mechanism: a port that will not bind returns early, and
/// the listeners bound before it are dropped on the way out, which closes them.
/// Nothing is ever left holding a socket that the caller has been told is not
/// there — a partially bound proxy reports [`ProxyListener::fully_bound`] as
/// false, and the caller's response to that is to point the sink at `0.0.0.0`,
/// after which nothing can arrive on the port that did bind anyway.
async fn bind_all(ports: &[(u16, Probe)]) -> Option<Vec<(TcpListener, Probe)>> {
    let mut bound = Vec::with_capacity(ports.len());
    for &(port, probe) in ports {
        bound.push((bind_loopback(port).await?, probe));
    }
    Some(bound)
}

/// Bind one port on `127.0.0.1`, or `None` with a warning.
///
/// The address is `127.0.0.1` and NEVER `0.0.0.0`, which is the difference
/// between a proxy reachable only by processes on this machine and one
/// reachable by anything on the network. `0.0.0.0` would invite every host on
/// the LAN — a coffee-shop Wi-Fi included — to feed hostile bytes to a parser
/// running as root, in exchange for nothing: the sink IP written into
/// `/etc/hosts` is a loopback address, so every connection we actually want
/// arrives on loopback.
async fn bind_loopback(port: u16) -> Option<TcpListener> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    match TcpListener::bind(addr).await {
        Ok(l) => Some(l),
        // Expected on a developer machine: something else already owns :80.
        // Not an error — the caller degrades the proxy and enforcement
        // carries on regardless.
        Err(e) => {
            warn!(?e, port, "could not bind loopback port — proxy degraded");
            None
        }
    }
}

/// Turns a flood of one kind of event into at most one log line per
/// [`LOG_INTERVAL`], carrying how many events there were.
///
/// Deliberately not shared and not atomic: one of these lives inside each
/// accept task, which is the only thing that touches it, so throttling costs a
/// comparison rather than a lock on the accept path.
struct Throttle {
    /// Events since the last line. Saturating, because the count is a hint and
    /// an overflow here would be a panic in a task that exists to survive
    /// abuse.
    since: u64,
    /// When the last line was emitted. `None` until the first event, so the
    /// first one is always reported at once — a condition that starts and stops
    /// inside one interval must still be visible.
    last: Option<Instant>,
}

impl Throttle {
    fn new() -> Self {
        Self {
            since: 0,
            last: None,
        }
    }

    /// Count one event, and report the number to log when a line is due.
    /// `None` means "counted, stay quiet".
    fn tick(&mut self) -> Option<u64> {
        self.since = self.since.saturating_add(1);
        let now = Instant::now();
        if self
            .last
            .is_some_and(|last| now.duration_since(last) < LOG_INTERVAL)
        {
            return None;
        }
        self.last = Some(now);
        Some(std::mem::replace(&mut self.since, 0))
    }
}

/// Accept forever, one short-lived task per connection, with the number of
/// those tasks capped by `permits`. Mirrors `ipc::serve`, including the
/// back-off on a failing `accept` so a persistent error cannot spin the
/// runtime.
///
/// Over the cap, a connection is closed immediately rather than queued.
/// Back-pressure by refusal is the point: a queue of accepted-but-unserved
/// connections is exactly the unbounded thing the cap exists to prevent, and it
/// would hold the descriptors anyway. A browser that gets a closed connection
/// shows the same failure it would if we had never bound the port, which is the
/// ordinary degraded behaviour of this whole module.
fn spawn_accept(listener: TcpListener, probe: Probe, permits: Arc<Semaphore>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut refusals = Throttle::new();
        let mut failures = Throttle::new();
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        // Closed here, before anything reads a byte from it.
                        drop(stream);
                        if let Some(n) = refusals.tick() {
                            warn!(
                                refused = n,
                                cap = MAX_CONNECTIONS,
                                "loopback proxy at its connection cap — \
                                 connections refused; blocking is unaffected"
                            );
                        }
                        continue;
                    };
                    tokio::spawn(async move {
                        handle(stream, probe).await;
                        // Held for exactly the life of the connection, however
                        // `handle` returned.
                        drop(permit);
                    });
                }
                Err(e) => {
                    // Throttled: under EMFILE this fires every ACCEPT_BACKOFF
                    // for as long as the pressure lasts, which is ten lines a
                    // second of the same line.
                    if let Some(n) = failures.tick() {
                        warn!(?e, failures = n, "loopback proxy accept failed");
                    }
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            }
        }
    })
}

/// Read a bounded head from one connection, then refuse it.
///
/// This stage does not forward: the hostname is read (the parsers are the
/// audited code the forwarding stage needs, so they stay wired in) but the
/// connection is always refused. On `:80` the static [`BLOCK_RESPONSE`] is
/// written and the socket closed; on `:443` the socket is closed with nothing
/// sent, so the browser shows its own connection error rather than a
/// certificate warning. The next commit is where a parsed hostname decides
/// whether to splice the connection on to the real site instead.
///
/// Everything that can go wrong here — a timeout, a reset, bytes that parse to
/// nothing — ends the same way: drop the connection silently. There is nothing
/// a caller could do about it and nothing worth logging per connection.
async fn handle(mut stream: TcpStream, probe: Probe) {
    let host = match tokio::time::timeout(READ_TIMEOUT, read_hostname(&mut stream, probe)).await {
        Ok(Some(h)) => h,
        // Timed out, hung up, or said something we could not read a hostname
        // out of. Refused all the same, by closing.
        _ => return,
    };
    // Read, but not acted on beyond a trace line this stage: no forwarding yet.
    debug!(%host, ?probe, "loopback proxy refusing blocked connection");
    if probe == Probe::Http {
        // One fixed byte string. On :443 this branch is not taken at all: no
        // handshake is attempted and no byte is ever written, so the browser
        // shows its own connection error rather than a certificate warning.
        let _ = tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(BLOCK_RESPONSE)).await;
    }
    // Close: the connection has told us everything it is ever going to.
    drop(stream);
}

/// Read at most [`MAX_READ`] bytes, trying the parser as soon as the bytes that
/// arrived could have completed the structure, so a well-formed request is
/// answered when it is complete rather than when the peer stops talking.
///
/// The buffer is allocated once at a FIXED size. Nothing on the wire chooses
/// it, and the loop cannot grow it.
async fn read_hostname(stream: &mut TcpStream, probe: Probe) -> Option<String> {
    let mut buf = vec![0u8; MAX_READ];
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = match stream.read(buf.get_mut(filled..)?).await {
            Ok(0) | Err(_) => break, // peer closed, or a broken connection
            Ok(n) => n,
        };
        let fresh = filled;
        filled = filled.saturating_add(n);
        let head = buf.get(..filled)?;
        if !parse_is_due(probe, head, fresh) {
            continue;
        }
        if let Some(host) = parse(probe, head) {
            return Some(host);
        }
    }
    // The read ended — the peer hung up, or the buffer is full — with the
    // structure still looking incomplete. One last parse, because "incomplete"
    // is the normal shape of a ClientHello whose record header claims more
    // bytes than ever arrived, and the hostname inside one that did arrive is
    // still worth having.
    parse(probe, buf.get(..filled)?)
}

/// Dispatch to the parser for `probe`. The port chooses this, never the bytes.
fn parse(probe: Probe, head: &[u8]) -> Option<String> {
    match probe {
        Probe::Http => parse_host_header(head),
        Probe::Tls => parse_sni(head),
    }
}

/// Whether the `head[fresh..]` that just arrived could have changed what a
/// parse would return.
///
/// Re-parsing the whole buffer after every chunk is quadratic in the number of
/// chunks, and the peer picks that number: a client dribbling one byte per
/// packet turned 8 KB into ~40 ms of root CPU, some 800× a real request, for a
/// hostname it was never going to send. The cap on concurrent connections and
/// [`READ_TIMEOUT`] both bound the damage, but the work was pointless in the
/// first place.
///
/// This decides only WHEN to parse, never what a parse means: both arms are
/// conservative, and the read loop parses once more when it ends, so no input
/// that used to yield a hostname stops doing so. Truncation still cannot lie —
/// the parsers, which are the thing that guarantees it, are untouched.
fn parse_is_due(probe: Probe, head: &[u8], fresh: usize) -> bool {
    match probe {
        // `split_line` only ever examines complete lines, so until a new LF
        // lands there is by construction nothing new to read.
        Probe::Http => head.get(fresh..).is_some_and(|new| new.contains(&b'\n')),
        // The declared record is all here, so the SNI extension either is too
        // or was never coming.
        Probe::Tls => tls_record_is_complete(head),
    }
}

/// Whether `head` holds the whole TLS record its own header declares: five
/// bytes of content type, legacy version and length, then that many more.
///
/// Goes through [`Cursor`] like the parser it gates, so a buffer too short to
/// hold even the header answers "not yet" instead of indexing off the end.
fn tls_record_is_complete(head: &[u8]) -> bool {
    let mut record = Cursor::new(head);
    // content_type(1) + version(2), then the length.
    if record.skip(3).is_none() {
        return false;
    }
    match record.u16() {
        Some(declared) => record.remaining() >= usize::from(declared),
        None => false,
    }
}

// ── parsers ─────────────────────────────────────────────────────────────────
//
// Pure functions over a byte slice, in the shape of the other pure helpers in
// this codebase (`lock_gate`, `evaluate_allowance`): no IO, no clock, no
// state, exhaustively unit-tested below. They are the security-critical part
// of this module — everything above is plumbing.

/// Extract the `Host:` value from an HTTP/1.x request head.
///
/// Deliberately not an HTTP parser: it reads header lines until the blank line
/// that ends the head and stops there. No body is read, `Content-Length` is
/// ignored entirely, and nothing is buffered on the strength of a number the
/// client supplied.
///
/// Returns the hostname lowercased, with any `:port` suffix removed, and only
/// if it looks like a hostname ([`plausible_hostname`]).
fn parse_host_header(buf: &[u8]) -> Option<String> {
    // Bound the scan whatever the caller passes: callers read at most
    // MAX_READ, but a pure function should not depend on its callers for that.
    let head = buf.get(..MAX_READ).unwrap_or(buf);
    // The request line is not a header; skipping it also means a buffer with
    // no line terminator at all yields nothing.
    let (_request_line, mut rest) = split_line(head)?;
    loop {
        let (line, tail) = split_line(rest)?;
        rest = tail;
        if line.is_empty() {
            // End of the head. Whatever follows is a body, which is not ours
            // to read.
            return None;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            // A header line with no colon is junk (or an obs-fold
            // continuation). Skip it rather than abandoning the head.
            continue;
        };
        let name = line.get(..colon)?.trim_ascii();
        if !name.eq_ignore_ascii_case(b"host") {
            continue;
        }
        let value = line.get(colon.checked_add(1)?..)?.trim_ascii();
        let value = std::str::from_utf8(value).ok()?;
        return hostname_from_str(strip_port(value));
    }
}

/// Split off one LF-terminated line, returning it (without its terminator, and
/// without a trailing CR) plus the rest.
///
/// `None` when there is no terminator left, which is the point: a `Host:` line
/// cut in half by the end of the read buffer would otherwise parse as a
/// truncated hostname — `reddit.co` for `reddit.com` — and a wrong answer here
/// is worse than none. Only complete lines are ever examined.
fn split_line(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let nl = buf.iter().position(|&b| b == b'\n')?;
    let line = buf.get(..nl)?;
    let line = match line.split_last() {
        Some((b'\r', head)) => head,
        _ => line,
    };
    Some((line, buf.get(nl.checked_add(1)?..)?))
}

/// Drop a trailing `:port`, and only that: the suffix is removed only when
/// everything after the last colon is a non-empty run of digits. So
/// `example.com:8080` loses its port, while `[::1]` keeps every character and
/// is then rejected by [`plausible_hostname`] for containing brackets.
fn strip_port(value: &str) -> &str {
    match value.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => value,
    }
}

/// Extract the SNI hostname from a TLS ClientHello.
///
/// Hand-rolled rather than pulling in a TLS crate: the walk is short enough to
/// audit in one sitting, and this codebase is deliberately dependency-thin. It
/// reads exactly the fields it needs to reach `server_name` and never
/// interprets anything else — no version negotiation, no cipher list, no
/// handshake state.
///
/// The structure, checked at every step:
///
/// ```text
/// record header    content_type(1)=0x16  version(2)  length(2)
/// handshake header msg_type(1)=0x01      length(3)
/// body             client_version(2)  random(32)
///                  session_id     u8-prefixed
///                  cipher_suites  u16-prefixed
///                  compression    u8-prefixed
///                  extensions     u16-prefixed, then repeated:
///                    ext_type(2)  ext_len(2)
///                    -- server_name (0x0000) --
///                    list_len(2)  name_type(1)=0x00  name_len(2)  name
/// ```
fn parse_sni(buf: &[u8]) -> Option<String> {
    let mut record = Cursor::new(buf.get(..MAX_READ).unwrap_or(buf));
    if record.u8()? != 0x16 {
        return None; // not a handshake record
    }
    record.skip(2)?; // legacy record version
    let record_len = record.u16()? as usize;
    // Truncation is tolerated on the OUTER containers only: a ClientHello can
    // be larger than one read, and a hostname that already arrived is still
    // worth having. Every read INSIDE stays exact, so a cut buffer can only
    // ever yield `None` — never a short or wrong name.
    let mut handshake = Cursor::new(record.take_at_most(record_len));
    if handshake.u8()? != 0x01 {
        return None; // handshake, but not a ClientHello
    }
    let handshake_len = handshake.u24()?;
    let mut body = Cursor::new(handshake.take_at_most(handshake_len));

    body.skip(2)?; // client_version
    body.skip(32)?; // random
    let session_id_len = body.u8()? as usize;
    body.skip(session_id_len)?;
    let cipher_suites_len = body.u16()? as usize;
    body.skip(cipher_suites_len)?;
    let compression_len = body.u8()? as usize;
    body.skip(compression_len)?;

    // No extensions block at all is legal (a very old ClientHello) and simply
    // carries no SNI.
    let extensions_len = body.u16()? as usize;
    let mut extensions = Cursor::new(body.take_at_most(extensions_len));
    while extensions.remaining() > 0 {
        let ext_type = extensions.u16()?;
        let ext_len = extensions.u16()? as usize;
        // Exact: an extension claiming more bytes than the block holds is
        // malformed, and guessing at its contents is how parsers get owned.
        let ext = extensions.take(ext_len)?;
        if ext_type == 0x0000 {
            return parse_server_name(ext);
        }
        // Any other extension type is skipped whole — `take` already advanced
        // past it.
    }
    None
}

/// The body of a `server_name` extension: a list of typed names, of which we
/// want the first `host_name` (type 0).
fn parse_server_name(ext: &[u8]) -> Option<String> {
    let mut list = Cursor::new(ext);
    let list_len = list.u16()? as usize;
    let mut names = Cursor::new(list.take(list_len)?);
    while names.remaining() > 0 {
        let name_type = names.u8()?;
        let name_len = names.u16()? as usize;
        // Exact again: this is the length that would index straight into the
        // hostname, so an overrun must fail rather than clamp.
        let name = names.take(name_len)?;
        if name_type == 0x00 {
            return hostname_from_bytes(name);
        }
    }
    None
}

/// Validate raw bytes as a hostname, then — and only then — allocate.
///
/// The length check comes first and the UTF-8 borrow second, so nothing is
/// copied on the strength of attacker-controlled bytes; the single
/// `to_ascii_lowercase` at the end is the only allocation in either parser.
fn hostname_from_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > MAX_HOSTNAME {
        return None;
    }
    hostname_from_str(std::str::from_utf8(bytes).ok()?)
}

/// As [`hostname_from_bytes`], for a value already known to be a `str`.
/// Lowercased because DNS names are case-insensitive and every consumer wants
/// to compare them against configured domains.
fn hostname_from_str(host: &str) -> Option<String> {
    if !plausible_hostname(host) {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// Whether `host` looks like a hostname: ASCII, within the DNS length limit,
/// and a dot-separated run of labels made of letters, digits and hyphens.
///
/// Strict on purpose. Anything reaching here came off the network, and it will
/// end up in a log line and a desktop notification — so no control characters,
/// no spaces, no percent-escapes, no wildcards, no `..`, and nothing that
/// could be read as a path or a shell word. An IDN arrives as punycode
/// (`xn--…`), which passes; raw UTF-8 does not, which is deliberate — a
/// hostname that renders as a lookalike of another one has no business in a
/// notification.
fn plausible_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOSTNAME || !host.is_ascii() {
        return false;
    }
    // A trailing dot is legal in DNS but never useful here, and rejecting it
    // keeps the label rule below to one case.
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            // RFC 1123: a label starts and ends with a letter or digit. This
            // is also what rejects a bare "-", which passes every other rule
            // here while being nobody's hostname.
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// A bounds-checked cursor over a byte slice.
///
/// Every read in the TLS walk goes through this, so "was the length checked
/// here?" has one answer for the whole parser instead of one per line. Each
/// method returns `None` the moment a read would pass the end, offsets advance
/// only by amounts already proven to fit, and additions are checked — so no
/// arithmetic can wrap into an index and no slice is ever indexed directly.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes left. Saturating, so the invariant `pos <= len` failing could
    /// still never underflow into a huge count.
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Exactly `n` bytes, or `None` if fewer remain.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    /// Up to `n` bytes: whatever is left when fewer remain. Used ONLY for the
    /// outer TLS containers, where a length larger than the buffer means the
    /// read was cut short rather than that the input is hostile — see the note
    /// in [`parse_sni`].
    fn take_at_most(&mut self, n: usize) -> &'a [u8] {
        let end = self.pos.saturating_add(n).min(self.buf.len());
        let out = self.buf.get(self.pos..end).unwrap_or(&[]);
        self.pos = end;
        out
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        let b: [u8; 1] = self.take(1)?.try_into().ok()?;
        Some(u8::from_be_bytes(b))
    }

    fn u16(&mut self) -> Option<u16> {
        let b: [u8; 2] = self.take(2)?.try_into().ok()?;
        Some(u16::from_be_bytes(b))
    }

    /// The 24-bit big-endian length in a handshake header. Returned as `usize`
    /// because its only use is a length, and it cannot exceed 2^24.
    fn u24(&mut self) -> Option<usize> {
        // Destructured rather than indexed, so this file contains no direct
        // index at all — three shifts of a u8 into a usize cannot overflow.
        let [hi, mid, lo]: [u8; 3] = self.take(3)?.try_into().ok()?;
        Some(((hi as usize) << 16) | ((mid as usize) << 8) | (lo as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── HTTP Host: header ───────────────────────────────────────────────────

    fn req(headers: &str) -> Vec<u8> {
        format!("GET / HTTP/1.1\r\n{headers}\r\n").into_bytes()
    }

    #[test]
    fn host_header_is_extracted() {
        assert_eq!(
            parse_host_header(&req("Host: reddit.com\r\n")),
            Some("reddit.com".to_string())
        );
    }

    #[test]
    fn host_header_is_case_insensitive_and_lowercased() {
        assert_eq!(
            parse_host_header(&req("hOsT:   ReDDit.COM  \r\n")),
            Some("reddit.com".to_string())
        );
    }

    #[test]
    fn host_header_port_suffix_is_stripped() {
        assert_eq!(
            parse_host_header(&req("Host: reddit.com:8080\r\n")),
            Some("reddit.com".to_string())
        );
        // Only a real numeric port: a colon followed by anything else leaves
        // the value alone, and the value is then rejected.
        assert_eq!(parse_host_header(&req("Host: reddit.com:hi\r\n")), None);
        assert_eq!(parse_host_header(&req("Host: reddit.com:\r\n")), None);
        assert_eq!(parse_host_header(&req("Host: [::1]:443\r\n")), None);
    }

    #[test]
    fn host_header_after_other_headers() {
        let r = req("User-Agent: curl/8\r\nAccept: */*\r\nHost: news.example\r\n");
        assert_eq!(parse_host_header(&r), Some("news.example".to_string()));
    }

    #[test]
    fn no_host_header_yields_none() {
        assert_eq!(parse_host_header(&req("User-Agent: curl/8\r\n")), None);
        assert_eq!(parse_host_header(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn malformed_request_lines_yield_none() {
        for raw in [
            &b""[..],
            b"\r\n",
            b"\n",
            b"GET",
            b"GET / HTTP/1.1",       // no terminator at all
            b"GET / HTTP/1.1\r\n",   // request line only
            b"\0\0\0\0\0\0\0\0\0\0", // not HTTP in any sense
            b"Host: reddit.com\r\n", // a header where the request line goes
        ] {
            assert_eq!(parse_host_header(raw), None, "raw {raw:?}");
        }
    }

    // A `Host:` line cut by the end of the read must never yield a truncated
    // hostname — `reddit.co` is a different site, and answering with it would
    // be worse than answering with nothing. Every prefix either parses to the
    // whole name (once the line is complete) or to nothing.
    #[test]
    fn host_header_split_across_the_buffer_end_never_truncates() {
        let full = req("Host: reddit.com\r\n");
        for cut in 0..full.len() {
            match parse_host_header(&full[..cut]) {
                None => {}
                Some(h) => assert_eq!(h, "reddit.com", "a prefix of {cut} bytes"),
            }
        }
        // Specifically: a cut inside the value yields nothing at all, because
        // the line has no terminator yet.
        assert_eq!(parse_host_header(&full[..30]), None);
        assert_eq!(
            parse_host_header(&full),
            Some("reddit.com".to_string()),
            "the complete request still parses"
        );
    }

    #[test]
    fn host_value_must_look_like_a_hostname() {
        for bad in [
            "Host: \r\n",
            "Host:\r\n",
            "Host: -\r\n",           // a bare hyphen is nobody's hostname
            "Host: a..b\r\n",        // empty label
            "Host: -reddit.com\r\n", // a label may not start with a hyphen…
            "Host: reddit-.com\r\n", // …nor end with one
            "Host: .reddit.com\r\n",
            "Host: reddit.com.\r\n", // trailing dot: legal DNS, rejected here
            "Host: red dit.com\r\n",
            "Host: reddit.com/../etc/passwd\r\n",
            "Host: red\u{00e9}dit.com\r\n", // non-ASCII
            "Host: reddit_com\r\n",
            "Host: <script>\r\n",
        ] {
            assert_eq!(parse_host_header(&req(bad)), None, "value {bad:?}");
        }
        // …and the hyphen case that IS a hostname, so the rule above is not
        // rejecting everything by accident.
        assert_eq!(
            parse_host_header(&req("Host: my-site.example\r\n")),
            Some("my-site.example".to_string())
        );
    }

    // A single header longer than anything real must neither parse nor cost
    // more than the bounded scan.
    #[test]
    fn absurdly_long_header_is_bounded() {
        let mut raw = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
        raw.extend(std::iter::repeat_n(b'A', 512 * 1024));
        raw.extend_from_slice(b"\r\nHost: reddit.com\r\n\r\n");
        // The Host: line sits past the scan limit, so it is never reached.
        assert_eq!(parse_host_header(&raw), None);

        // A hostname past the DNS length limit is refused outright.
        let long = "a".repeat(MAX_HOSTNAME + 1);
        assert_eq!(parse_host_header(&req(&format!("Host: {long}\r\n"))), None);
        // One label may not exceed 63 bytes either.
        let long_label = "a".repeat(64);
        assert_eq!(
            parse_host_header(&req(&format!("Host: {long_label}.com\r\n"))),
            None
        );
    }

    #[test]
    fn header_after_the_blank_line_is_never_read() {
        // Anything past the empty line is a body. A `Host:` in it is not a
        // header, and reading one would mean parsing a body.
        let raw = b"GET / HTTP/1.1\r\n\r\nHost: reddit.com\r\n";
        assert_eq!(parse_host_header(raw), None);
    }

    #[test]
    fn bare_lf_line_endings_are_accepted() {
        // Not conformant, but trivially produced by hand-written clients and
        // costs nothing to accept.
        assert_eq!(
            parse_host_header(b"GET / HTTP/1.1\nHost: reddit.com\n\n"),
            Some("reddit.com".to_string())
        );
    }

    // ── TLS ClientHello / SNI ───────────────────────────────────────────────

    /// Build a ClientHello of the shape a real client sends: correct record
    /// and handshake headers, a 32-byte random, a session id, cipher suites,
    /// compression, and an extensions block. `extensions` is the pre-encoded
    /// extension list.
    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(32); // session_id length
        body.extend_from_slice(&[0x22; 32]); // session_id
        body.extend_from_slice(&[0x00, 0x04]); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
        body.push(1); // compression methods length
        body.push(0); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = vec![0x01]; // client_hello
        let len = body.len();
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01]; // handshake, legacy version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// A `server_name` extension carrying one `host_name`.
    fn sni_extension(host: &[u8]) -> Vec<u8> {
        let mut name = vec![0x00]; // name_type: host_name
        name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        name.extend_from_slice(host);

        let mut list = (name.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&name);

        let mut ext = vec![0x00, 0x00]; // extension_type: server_name
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
        ext
    }

    /// An extension of some other type, with `len` bytes of filler — the
    /// things a real ClientHello carries before (and after) its SNI.
    fn other_extension(ext_type: u16, len: usize) -> Vec<u8> {
        let mut ext = ext_type.to_be_bytes().to_vec();
        ext.extend_from_slice(&(len as u16).to_be_bytes());
        ext.extend(std::iter::repeat_n(0x5a, len));
        ext
    }

    fn hello_for(host: &str) -> Vec<u8> {
        client_hello(&sni_extension(host.as_bytes()))
    }

    #[test]
    fn sni_is_extracted_from_a_realistic_client_hello() {
        assert_eq!(
            parse_sni(&hello_for("reddit.com")),
            Some("reddit.com".to_string())
        );
    }

    #[test]
    fn sni_is_found_after_other_extensions() {
        // GREASE, supported_versions, key_share… whatever precedes it, the
        // walk must skip extensions it does not care about and keep going.
        let mut exts = other_extension(0x0a0a, 2); // GREASE
        exts.extend(other_extension(0x002b, 5)); // supported_versions-ish
        exts.extend(other_extension(0x0033, 40)); // key_share-ish
        exts.extend(sni_extension(b"news.example"));
        exts.extend(other_extension(0x0015, 100)); // padding, after the SNI
        assert_eq!(
            parse_sni(&client_hello(&exts)),
            Some("news.example".to_string())
        );
    }

    #[test]
    fn sni_hostname_is_lowercased() {
        assert_eq!(
            parse_sni(&hello_for("ReDDit.COM")),
            Some("reddit.com".to_string())
        );
    }

    #[test]
    fn no_extensions_at_all_yields_none() {
        assert_eq!(parse_sni(&client_hello(&[])), None);
    }

    #[test]
    fn extensions_without_server_name_yield_none() {
        let mut exts = other_extension(0x002b, 5);
        exts.extend(other_extension(0x0033, 40));
        assert_eq!(parse_sni(&client_hello(&exts)), None);
    }

    #[test]
    fn zero_length_extensions_are_skipped() {
        let mut exts = other_extension(0x0a0a, 0);
        exts.extend(other_extension(0x001b, 0));
        exts.extend(sni_extension(b"reddit.com"));
        assert_eq!(
            parse_sni(&client_hello(&exts)),
            Some("reddit.com".to_string())
        );
    }

    #[test]
    fn a_non_handshake_record_yields_none() {
        let mut hello = hello_for("reddit.com");
        hello[0] = 0x17; // application_data
        assert_eq!(parse_sni(&hello), None);
        // …and neither does anything else that is not TLS.
        assert_eq!(
            parse_sni(b"GET / HTTP/1.1\r\nHost: reddit.com\r\n\r\n"),
            None
        );
    }

    #[test]
    fn a_handshake_that_is_not_a_client_hello_yields_none() {
        let mut hello = hello_for("reddit.com");
        hello[5] = 0x02; // server_hello
        assert_eq!(parse_sni(&hello), None);
        hello[5] = 0x0b; // certificate
        assert_eq!(parse_sni(&hello), None);
    }

    // THE truncation test: every prefix of a valid ClientHello — which cuts at
    // every length boundary in the structure, one byte at a time — must either
    // yield nothing or the correct name, and must never panic. A short or
    // wrong hostname would be worse than no hostname.
    #[test]
    fn truncation_at_every_boundary_never_panics_or_lies() {
        let hello = hello_for("reddit.com");
        for cut in 0..hello.len() {
            match parse_sni(&hello[..cut]) {
                None => {}
                Some(h) => panic!("prefix of {cut} bytes produced {h:?}"),
            }
        }
        assert_eq!(parse_sni(&hello), Some("reddit.com".to_string()));
    }

    // Truncation with the hostname already on the wire: the outer containers
    // tolerate a cut (a ClientHello can outrun one read) while every inner
    // read stays exact, so the name that arrived is still readable.
    #[test]
    fn truncated_outer_length_still_finds_an_arrived_name() {
        let mut hello = hello_for("reddit.com");
        // Claim a record 4 KB longer than what follows.
        let claimed = u16::from_be_bytes([hello[3], hello[4]]).saturating_add(4096);
        hello[3..5].copy_from_slice(&claimed.to_be_bytes());
        assert_eq!(parse_sni(&hello), Some("reddit.com".to_string()));
    }

    #[test]
    fn a_name_len_that_overruns_the_buffer_yields_none() {
        let mut ext = sni_extension(b"reddit.com");
        // name_len sits at: ext_type(2) ext_len(2) list_len(2) name_type(1).
        let at = 7;
        ext[at..at + 2].copy_from_slice(&0xff00u16.to_be_bytes());
        assert_eq!(parse_sni(&client_hello(&ext)), None);

        // The same lie one level up: an extension claiming more than the
        // extensions block holds.
        let mut ext = sni_extension(b"reddit.com");
        ext[2..4].copy_from_slice(&0xff00u16.to_be_bytes());
        assert_eq!(parse_sni(&client_hello(&ext)), None);

        // …and one level up again: the server_name list length.
        let mut ext = sni_extension(b"reddit.com");
        ext[4..6].copy_from_slice(&0xff00u16.to_be_bytes());
        assert_eq!(parse_sni(&client_hello(&ext)), None);
    }

    #[test]
    fn an_empty_hostname_yields_none() {
        assert_eq!(parse_sni(&client_hello(&sni_extension(b""))), None);
    }

    #[test]
    fn a_non_ascii_or_implausible_hostname_yields_none() {
        for host in [
            &b"redd\xc3\xa9it.com"[..], // valid UTF-8, not ASCII
            b"redd\xffit.com",          // not even valid UTF-8
            b"redd it.com",
            b"reddit.com\n",
            b"reddit.com\0",
            b"../../etc/passwd",
            b"*.reddit.com",
            b".reddit.com",
        ] {
            assert_eq!(
                parse_sni(&client_hello(&sni_extension(host))),
                None,
                "host {host:?}"
            );
        }
    }

    #[test]
    fn a_name_type_other_than_host_name_yields_none() {
        let mut ext = sni_extension(b"reddit.com");
        ext[6] = 0x01; // some other NameType
        assert_eq!(parse_sni(&client_hello(&ext)), None);
    }

    // ── the fuzz sweep ──────────────────────────────────────────────────────

    /// A cheap deterministic PRNG: no dev-dependency, and a failure reproduces
    /// exactly. xorshift64*.
    fn prng(mut seed: u64) -> impl FnMut() -> u64 {
        move || {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            seed.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    /// Whether `host` is a run of bytes that was actually IN `input`.
    ///
    /// The oracle for the whole sweep. A parser may return nothing, or it may
    /// return something it read — but a name assembled out of two places, or
    /// conjured from a length field pointing at uninitialised buffer, appears
    /// nowhere contiguously and fails here. Case-insensitive, because both
    /// parsers lowercase what they return.
    fn appears_contiguously(host: &str, input: &[u8]) -> bool {
        !host.is_empty()
            && input.len() >= host.len()
            && input
                .windows(host.len())
                .any(|w| w.eq_ignore_ascii_case(host.as_bytes()))
    }

    // Neither parser may panic on ANY input, and neither may report a hostname
    // it was not given. A budgeted mutation sweep over a valid ClientHello and
    // a valid request head: every truncation, every 16-bit field in turn
    // replaced by the lengths that break naive parsers, a repeated
    // `server_name`, and random byte pokes.
    //
    // Both halves of the assertion matter. The panic half is what the
    // privilege-separation note at the top of this file rests on, and it is
    // load-bearing: a fixed handful of random buffers is not a sweep, and one
    // of those missed a panic that the truncation test caught. The hostname
    // half is the stronger claim — that a wrong answer is impossible, not just
    // improbable — extended from prefixes of a valid hello to structures no
    // client would ever send.
    #[test]
    fn mutated_client_hellos_never_panic_or_invent_a_hostname() {
        // The budget, and the reason this is a sweep rather than a fixed list:
        // a mutation space this large is only covered by volume. Half a million
        // parses over ~100-byte buffers is around a second in debug, which is
        // what a test that runs on every commit can afford to spend.
        const POKES: usize = 250_000;

        let hello = hello_for("reddit.com");
        let request = req("Host: reddit.com\r\n");

        // Both parsers on every buffer: the port picks one in production, but
        // neither may misbehave on bytes meant for the other.
        let check = |buf: &[u8]| {
            for host in [parse_sni(buf), parse_host_header(buf)]
                .into_iter()
                .flatten()
            {
                assert!(
                    appears_contiguously(&host, buf),
                    "parsed {host:?}, which is not in {buf:?}"
                );
            }
        };

        // Every truncation of both seeds.
        for seed in [&hello, &request] {
            for cut in 0..=seed.len() {
                check(&seed[..cut]);
            }
        }

        // Every 16-bit window of the ClientHello, in turn, overwritten with the
        // lengths that break naive parsers: nothing, everything, and just past
        // the end. Each mutant is also checked cut in half, so a lie about a
        // length is combined with the buffer actually ending early.
        let past_end = u16::try_from(hello.len()).unwrap().saturating_add(1);
        for at in 0..hello.len().saturating_sub(1) {
            for claim in [0u16, 1, 0xffff, past_end] {
                let mut mutant = hello.clone();
                mutant[at..at + 2].copy_from_slice(&claim.to_be_bytes());
                check(&mutant);
                check(&mutant[..mutant.len() / 2]);
            }
        }

        // A repeated `server_name`, which no client sends and the RFC forbids:
        // the walk must take the first and must not splice the others into it.
        let mut repeated = sni_extension(b"reddit.com");
        repeated.extend(sni_extension(b"example.test"));
        repeated.extend(other_extension(0x0015, 8));
        repeated.extend(sni_extension(b"third.test"));
        let repeated = client_hello(&repeated);
        assert_eq!(
            parse_sni(&repeated).as_deref(),
            Some("reddit.com"),
            "the first server_name is the answer"
        );
        for cut in 0..=repeated.len() {
            check(&repeated[..cut]);
        }

        // Random pokes, alternating between the two seeds, each mutant checked
        // whole and cut at a random offset.
        let mut next = prng(0x2545_f491_4f6c_dd1d);
        for i in 0..POKES {
            let mut mutant = if i % 2 == 0 {
                hello.clone()
            } else {
                request.clone()
            };
            for _ in 0..=(next() % 8) {
                let at = next() as usize % mutant.len();
                mutant[at] = next() as u8;
            }
            check(&mutant);
            let cut = next() as usize % (mutant.len() + 1);
            check(&mutant[..cut]);
        }
    }

    // ── the static :80 response ─────────────────────────────────────────────

    // The declared Content-Length must match the body, or a browser hangs
    // waiting for bytes that are never coming. Hand-written constant, so this
    // catches an edit to the text that forgets the number.
    #[test]
    fn block_response_content_length_matches_its_body() {
        let split = BLOCK_RESPONSE
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("headers and body are separated");
        let head = std::str::from_utf8(&BLOCK_RESPONSE[..split]).unwrap();
        let body_len = BLOCK_RESPONSE.len() - split - 4;
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .expect("Content-Length is declared")
            .trim()
            .parse()
            .unwrap();
        assert_eq!(declared, body_len);
    }

    // ── the connection path ─────────────────────────────────────────────────
    //
    // Port 0, never 80 or 443: the daemon on this machine may well own those,
    // and a test that fights it would be both flaky and rude.

    /// Bind an ephemeral loopback port and serve it with `probe`, returning the
    /// address and the accept task.
    async fn ephemeral(probe: Probe) -> (SocketAddr, JoinHandle<()>) {
        ephemeral_with_budget(probe, MAX_CONNECTIONS).await
    }

    /// As [`ephemeral`], with the connection budget under the test's control so
    /// the refusal path can be reached without opening [`MAX_CONNECTIONS`]
    /// sockets.
    async fn ephemeral_with_budget(probe: Probe, budget: usize) -> (SocketAddr, JoinHandle<()>) {
        let listener = ephemeral_listener().await;
        let addr = listener.local_addr().unwrap();
        let task = spawn_accept(listener, probe, Arc::new(Semaphore::new(budget)));
        (addr, task)
    }

    /// A listener on an ephemeral loopback port — port 0, never 80 or 443.
    async fn ephemeral_listener() -> TcpListener {
        TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("an ephemeral loopback port is always available")
    }

    /// The number of a loopback port that is free right now: bound to learn
    /// which one the kernel picked, then released.
    async fn free_port() -> u16 {
        let listener = ephemeral_listener().await;
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    /// Longer than any timeout in this module is allowed to be, and far shorter
    /// than a timeout accidentally left in hours. Every test that waits for the
    /// server to give up waits at most this long, so a mutant that turns a
    /// timeout into 3600 s fails the suite instead of hanging it.
    const PATIENCE: Duration = Duration::from_secs(30);

    // An HTTP connection that names a blocked host is refused with the one
    // static 403 and then closed — this stage forwards nothing.
    #[tokio::test]
    async fn http_connection_is_refused_with_the_static_response() {
        let (addr, task) = ephemeral(Probe::Http).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&req("Host: reddit.com\r\n"))
            .await
            .unwrap();

        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, BLOCK_RESPONSE, "the one static response, then close");
        task.abort();
    }

    // A TLS connection is refused by closing with nothing sent: no handshake,
    // no alert, no certificate — so the browser shows its own error instead of
    // a trust prompt.
    #[tokio::test]
    async fn tls_connection_is_refused_with_no_bytes_at_all() {
        let (addr, task) = ephemeral(Probe::Tls).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&hello_for("reddit.com")).await.unwrap();

        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty(), "expected no response, got {got:?}");
        task.abort();
    }

    // A connection that says nothing meaningful and hangs up is dropped with
    // no response — the ordinary shape of a port scan.
    #[tokio::test]
    async fn a_connection_with_nothing_to_say_gets_no_response() {
        let (addr, task) = ephemeral(Probe::Tls).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"hello?").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty());
        task.abort();
    }

    // ── where it binds ──────────────────────────────────────────────────────

    // `0.0.0.0` would invite every host on the LAN — a coffee-shop Wi-Fi
    // included — to feed hostile bytes to a parser running as root, in exchange
    // for nothing, since the sink written into /etc/hosts is a loopback
    // address. The rule is six lines of doc comment on `bind_loopback` and was
    // pinned by no test at all: the address could have been changed to
    // `0.0.0.0` and the suite would have stayed green. Asserted through the
    // real helper, on the address the kernel says the socket ended up on.
    #[tokio::test]
    async fn the_bind_helper_binds_loopback_and_never_every_interface() {
        let listener = bind_loopback(0)
            .await
            .expect("an ephemeral port always binds");
        let addr = listener.local_addr().unwrap();
        assert_eq!(
            addr.ip(),
            Ipv4Addr::LOCALHOST,
            "the proxy must be reachable only from this machine"
        );
        assert_ne!(
            addr.ip(),
            Ipv4Addr::UNSPECIFIED,
            "0.0.0.0 exposes a root parser to the network"
        );
    }

    // ── the timeouts ────────────────────────────────────────────────────────

    // A peer that connects and then says nothing must be hung up on, or it
    // holds a task and a descriptor for as long as it likes — the shape of the
    // exhaustion that stops the daemon re-applying blocks. Behavioural, because
    // the constant alone proves nothing about whether it is applied.
    #[tokio::test]
    async fn a_silent_connection_is_closed_at_the_read_timeout() {
        let (addr, task) = ephemeral(Probe::Tls).await;
        let mut client = TcpStream::connect(addr).await.unwrap();

        let opened = Instant::now();
        let mut got = Vec::new();
        // Bounded by PATIENCE and not by READ_TIMEOUT: a mutant that turns the
        // timeout into an hour must fail this test rather than hang it.
        let closed = tokio::time::timeout(PATIENCE, client.read_to_end(&mut got)).await;
        let waited = opened.elapsed();

        assert!(
            matches!(closed, Ok(Ok(0))),
            "the server must hang up on a silent peer, got {closed:?} after {waited:?}"
        );
        assert!(got.is_empty(), "and never speak on the :443 path");
        assert!(
            waited < PATIENCE,
            "a silent connection was held {waited:?} — the read timeout is not being applied"
        );
        assert!(
            waited >= READ_TIMEOUT / 2,
            "closed after {waited:?}, which is too soon to have been the timeout"
        );
        task.abort();
    }

    // The write half cannot be driven to its timeout from a test: BLOCK_RESPONSE
    // is 120 bytes, no socket send buffer Linux hands out is small enough to
    // make `write_all` of that block, and so no peer — however rude — can hold
    // it open. What the constant is for is the day the response grows or the
    // socket is not a loopback one, and the value is what MAX_CONNECTIONS is
    // sized against: cap × (read + write) is the worst-case descriptor-seconds
    // one attacker can buy. So it is pinned as a value, because raising either
    // constant to an hour otherwise leaves the whole suite green.
    #[test]
    fn the_connection_timeouts_stay_within_seconds() {
        assert!(
            READ_TIMEOUT <= Duration::from_secs(10),
            "a connection may not hold a task for {READ_TIMEOUT:?}"
        );
        assert!(
            WRITE_TIMEOUT <= Duration::from_secs(10),
            "a peer that will not read may not hold a task for {WRITE_TIMEOUT:?}"
        );
        assert!(
            READ_TIMEOUT.saturating_add(WRITE_TIMEOUT) < PATIENCE,
            "one connection's total budget must stay inside what the \
             behavioural tests above are willing to wait"
        );
    }

    // ── binding, releasing, dropping ────────────────────────────────────────

    // One port short is not a proxy: the caller's answer to a degraded proxy
    // is a sink of 0.0.0.0, after which nothing can arrive on the port that did
    // bind, so keeping it means root squatting :80 for traffic that can never
    // come.
    #[tokio::test]
    async fn a_partial_bind_keeps_no_port_at_all() {
        // The shape of a machine where something else already owns :443.
        let squatter = ephemeral_listener().await;
        let taken = squatter.local_addr().unwrap().port();
        let free = free_port().await;

        assert!(
            bind_all(&[(free, Probe::Http), (taken, Probe::Tls)])
                .await
                .is_none(),
            "binding is all-or-nothing"
        );
        TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, free)))
            .await
            .expect("the port that did bind must have been released again");
    }

    // `release` does not return until the ports are actually free. `abort`
    // alone returns before the runtime has dropped the task's future and the
    // `TcpListener` it owns, and a caller that releases and re-binds inside one
    // tick — one block ending as another starts — then gets EADDRINUSE and
    // silently loses the proxy until the next natural transition. So: no retry
    // loop here, deliberately. The very next bind must succeed.
    #[tokio::test]
    async fn release_frees_every_port_before_it_returns() {
        let http = ephemeral_listener().await;
        let tls = ephemeral_listener().await;
        let addrs = [http.local_addr().unwrap(), tls.local_addr().unwrap()];

        let running = ProxyListener::serve(vec![(http, Probe::Http), (tls, Probe::Tls)]);
        assert!(running.fully_bound(), "both ports were handed over");
        running.release().await;

        for addr in addrs {
            TcpListener::bind(addr)
                .await
                .expect("release must not return before the port is bindable");
        }
    }

    // Dropping a `ProxyListener` must free the ports too. Dropping a tokio
    // `JoinHandle` DETACHES its task rather than stopping it, so without a
    // `Drop` impl the accept tasks here would run for the life of the process —
    // ports 80 and 443 held by root, still answering, until the daemon
    // restarts.
    #[tokio::test]
    async fn dropping_a_listener_frees_its_port() {
        let listener = ephemeral_listener().await;
        let addr = listener.local_addr().unwrap();
        let running = ProxyListener::serve(vec![(listener, Probe::Http)]);
        assert!(
            !running.fully_bound(),
            "one listener out of two is not fully bound"
        );
        assert!(
            TcpListener::bind(addr).await.is_err(),
            "the port is held while the listener is alive"
        );

        drop(running);
        // `drop` aborts but cannot await, so the runtime frees the socket a
        // moment later; retry briefly rather than sleeping a fixed amount and
        // hoping. `release` is the path that also guarantees the *when*.
        for _ in 0..200 {
            if TcpListener::bind(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("dropping the listener never freed port {}", addr.port());
    }

    // Over the cap the connection is closed at once, not queued: an accepted
    // connection is a descriptor held for up to READ_TIMEOUT, and running the
    // daemon out of descriptors stops it re-applying blocks. `accept` is FIFO,
    // so the connection made first is the one holding the only permit.
    #[tokio::test]
    async fn a_connection_over_the_cap_is_refused_at_once() {
        let (addr, task) = ephemeral_with_budget(Probe::Http, 1).await;
        // Connects first and then says nothing, so it holds the one permit for
        // the whole READ_TIMEOUT.
        let _hog = TcpStream::connect(addr).await.unwrap();

        let mut refused = TcpStream::connect(addr).await.unwrap();
        let mut got = Vec::new();
        let closed = tokio::time::timeout(READ_TIMEOUT / 2, refused.read_to_end(&mut got)).await;
        assert!(
            matches!(closed, Ok(Ok(0))),
            "expected an immediate close with no bytes, got {closed:?}"
        );
        assert!(got.is_empty(), "a refused connection is never spoken to");
        task.abort();
    }

    // The refusal and accept-failure logs are driven by whoever is hammering
    // the port, so they report the first event at once and then a count.
    #[test]
    fn the_log_throttle_speaks_once_then_counts() {
        let mut throttle = Throttle::new();
        assert_eq!(throttle.tick(), Some(1), "the first event is always seen");
        for _ in 0..1_000 {
            assert_eq!(throttle.tick(), None, "the rest are counted in silence");
        }
        // Once an interval has passed, the line that is due carries everything
        // since the last one. (`checked_sub` rather than `-`: on a machine that
        // booted seconds ago the subtraction has nowhere to go, and `None`
        // takes the same branch as a first event.)
        throttle.last = Instant::now().checked_sub(LOG_INTERVAL);
        assert_eq!(throttle.tick(), Some(1_001));
        assert_eq!(throttle.tick(), None, "and the count starts again");
    }
}
