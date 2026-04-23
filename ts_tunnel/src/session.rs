use core::fmt::{Debug, Formatter};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use ts_bitset::Bitset;
use ts_packet::PacketMut;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned,
    little_endian::{U32, U64},
};

use crate::messages::{SessionId, TransportDataHeader};

type SessionKey = chacha20poly1305::Key;

/// A generator of monotonically increasing 64-bit nonces.
#[derive(Default)]
struct NonceGenerator {
    nonce: Mutex<u64>,
}

impl NonceGenerator {
    /// Reserve a batch of consecutive nonces.
    ///
    /// The reserved range is fully consumed even if the returned NonceIter isn't.
    fn batch(&self, num: usize) -> NonceIter {
        let mut nonce = self.nonce.lock().unwrap();
        let end = match nonce.checked_add(num as u64) {
            Some(end) => end,
            // NonceGenerator is used to produce nonces for a wireguard session.
            // A single wireguard session lives for 120s before being replaced.
            // To exhaust a u64 in that time, assuming 1500b packets, you would
            // have to be sending 27.6 zettabytes every two minutes, or 230
            // exabytes/sec.
            //
            // If you're still running this code on a computer capable of that
            // kind of data rate: hello from the past! Enjoy your panic.
            None => panic!("nonce exhausted"),
        };
        let ret = NonceIter { cur: *nonce, end };
        *nonce = end;
        ret
    }
}
struct NonceIter {
    cur: u64,
    end: u64,
}

impl Iterator for NonceIter {
    type Item = Nonce;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur == self.end {
            None
        } else {
            let ret = self.cur;
            self.cur += 1;
            Some(Nonce::from(ret))
        }
    }
}

/// A cryptographic nonce for use with ChaCha20Poly1305.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
struct Nonce {
    _zero: U32,
    counter: U64,
}

impl From<U64> for Nonce {
    fn from(v: U64) -> Self {
        Nonce {
            counter: v,
            _zero: Default::default(),
        }
    }
}

impl From<u64> for Nonce {
    fn from(v: u64) -> Self {
        Self::from(U64::from(v))
    }
}

impl AsRef<chacha20poly1305::Nonce> for Nonce {
    fn as_ref(&self) -> &chacha20poly1305::Nonce {
        let array: &[u8] = self.as_bytes();
        array.into()
    }
}

/// Established session that can only send.
pub struct TransmitSession {
    cipher: ChaCha20Poly1305,
    nonce: NonceGenerator,
    id: SessionId,
    created: Instant,
}

impl TransmitSession {
    pub fn new(key: SessionKey, id: SessionId, now: Instant) -> Self {
        TransmitSession {
            cipher: ChaCha20Poly1305::new(&key),
            nonce: Default::default(),
            id,
            created: now,
        }
    }

    /// Encrypt a batch of packets.
    pub fn encrypt<'a, Into, Iter>(&self, packets: Into)
    where
        Iter: ExactSizeIterator<Item = &'a mut PacketMut>,
        Into: IntoIterator<Item = &'a mut PacketMut, IntoIter = Iter>,
    {
        let packets = packets.into_iter();
        let nonce = self.nonce.batch(packets.len());
        for (packet, nonce) in packets.zip(nonce) {
            // Session encryption only fails if the provided packet can't grow, which ours can.
            self.cipher
                .encrypt_in_place(nonce.as_ref(), &[], packet)
                .unwrap();
            let header = TransportDataHeader {
                receiver_id: self.id,
                nonce: nonce.counter,
                ..Default::default()
            };
            packet.grow_front(size_of::<TransportDataHeader>());
            // Write only fails if the packet is too small, and we just extended it to have
            // enough space.
            header.write_to_prefix(packet.as_mut()).unwrap();
        }
    }

    pub fn stale(&self, now: Instant) -> bool {
        now.duration_since(self.created) > Duration::from_secs(120) // TODO: constants
    }

    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) > Duration::from_secs(240) // TODO: constants
    }
}

/// The number of bits in the replay window.
///
/// This is the number of past nonces (relative to the highest seen) that
/// the filter tracks. 128 is the standard WireGuard window size, matching
/// the reference implementation and the Linux kernel module.
const REPLAY_WINDOW_SIZE: u64 = 128;

/// A sliding-window replay filter for WireGuard transport data nonces.
///
/// Tracks a window of recently received 64-bit counters to reject replayed
/// or too-old packets. Per WireGuard spec section 5.4.6, the replay check
/// is performed AFTER successful AEAD decryption to prevent DoS via forged
/// counter values.
///
/// The window uses a [`Bitset<2>`] (128 bits) where bit 0 represents
/// `high_mark`, bit 1 represents `high_mark - 1`, and so on.
pub(crate) struct ReplayFilter {
    /// The highest counter value successfully received and accepted.
    high_mark: u64,
    /// Bitmap tracking which of the last `REPLAY_WINDOW_SIZE` counters
    /// have been received. Bit 0 = `high_mark`, bit 1 = `high_mark - 1`, etc.
    window: Bitset<2>,
    /// Whether any counter has ever been accepted. False only before the
    /// first packet.
    initialized: bool,
}

impl ReplayFilter {
    /// Create a new replay filter with no packets seen.
    fn new() -> Self {
        Self {
            high_mark: 0,
            window: Bitset::EMPTY,
            initialized: false,
        }
    }

    /// Check whether a counter value is acceptable (not a replay, not too old)
    /// and, if so, record it as seen.
    ///
    /// Returns `true` if the counter is accepted, `false` if it should be
    /// rejected as a replay or as too old.
    ///
    /// This method must only be called AFTER successful AEAD decryption.
    fn check_and_update(&mut self, counter: u64) -> bool {
        if !self.initialized {
            // First packet ever: accept and initialize.
            self.high_mark = counter;
            self.window = Bitset::EMPTY;
            self.window.set(0);
            self.initialized = true;
            return true;
        }

        if counter > self.high_mark {
            // New highest counter: slide the window forward.
            let shift = counter - self.high_mark;
            if shift >= REPLAY_WINDOW_SIZE {
                // The entire window is obsolete.
                self.window = Bitset::EMPTY;
            } else {
                self.window <<= shift as usize;
            }
            self.window.set(0);
            self.high_mark = counter;
            return true;
        }

        // counter <= high_mark: check if it's within the window.
        let offset = self.high_mark - counter;
        if offset >= REPLAY_WINDOW_SIZE {
            // Too old: outside the window.
            return false;
        }

        let bit = offset as usize;
        if self.window.test(bit) {
            // Already seen: replay.
            return false;
        }

        // Within window and not yet seen: accept.
        self.window.set(bit);
        true
    }
}

impl Debug for ReplayFilter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayFilter")
            .field("high_mark", &self.high_mark)
            .field("initialized", &self.initialized)
            .finish_non_exhaustive()
    }
}

/// Established session that can only receive.
pub struct ReceiveSession {
    cipher: ChaCha20Poly1305,
    id: SessionId,
    created: Instant,
    replay: Mutex<Box<ReplayFilter>>,
}

impl Debug for ReceiveSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiveSession")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl ReceiveSession {
    pub fn new(key: SessionKey, id: SessionId, now: Instant) -> Self {
        ReceiveSession {
            cipher: ChaCha20Poly1305::new(&key),
            id,
            created: now,
            replay: Mutex::new(Box::new(ReplayFilter::new())),
        }
    }

    /// Decrypt wireguard transport data messages in place.
    ///
    /// Returns the packets which successfully decrypted.
    pub fn decrypt(&self, mut packets: Vec<PacketMut>) -> Vec<PacketMut> {
        packets.retain_mut(|packet| self.decrypt_one(packet));
        packets
    }

    /// Decrypt a wireguard transport data message in place.
    #[tracing::instrument(skip_all, fields(session_id = ?self.id))]
    #[must_use]
    fn decrypt_one(&self, pkt: &mut PacketMut) -> bool {
        let Ok((header, _)) = TransportDataHeader::try_ref_from_prefix(pkt.as_ref()) else {
            tracing::warn!("decode as transport packet failed");
            return false;
        };

        let _guard = tracing::trace_span!("header_parsed", ?header).entered();

        if header.receiver_id != self.id {
            // Technically an unnecessary check, because a bespoke session is created for each
            // session ID, with different AEAD keys. So, if the caller mistakenly hands the wrong
            // packet to a session, it'll always fail to decrypt below. But, comparing one u32
            // is cheaper than getting partway through AEAD decryption before finding that the
            // authenticator is wrong, so might as well take the shortcut.
            //
            // Passing the wrong packet to a session is also a programmer error, so scream a bit
            // more loudly in debug builds.
            tracing::error!(message_session_id = ?header.receiver_id, "wrong receiver id");

            debug_assert!(
                false,
                "decrypt_in_place given packet with wrong receiver ID"
            );

            return false;
        }

        let nonce = Nonce::from(header.nonce);
        let counter = u64::from(header.nonce);
        pkt.truncate_front(size_of::<TransportDataHeader>());

        let result = self.cipher.decrypt_in_place(nonce.as_ref(), &[], pkt);

        if let Err(e) = &result {
            tracing::error!(err = %e, "decryption failed");
            return false;
        }

        // Replay check AFTER successful AEAD decryption, per WireGuard spec
        // section 5.4.6. Checking before decryption would allow an attacker
        // to DoS by sending packets with valid-looking counters but invalid
        // AEAD tags, poisoning the replay window.
        let mut replay = self.replay.lock().unwrap();
        if !replay.check_and_update(counter) {
            tracing::warn!(counter, "replay detected, dropping packet");
            return false;
        }

        true
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) > Duration::from_secs(240) // TODO: constants
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Message;

    #[test]
    fn test_session() {
        let k: [u8; 32] = rand::random();
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now);
        let recv = ReceiveSession::new(k.into(), session, now);

        const CLEARTEXT: &[u8] = b"foobar";
        let mut pkt = [PacketMut::from(CLEARTEXT)];

        send.encrypt(&mut pkt);
        assert_eq!(pkt[0].len(), 38);
        let Ok(Message::TransportDataHeader(msg)) = Message::try_from(pkt[0].as_ref()) else {
            panic!("packet is not a valid TransportData message");
        };
        assert_eq!(msg.receiver_id, session);
        assert_eq!(u64::from(msg.nonce), 0);

        assert!(recv.decrypt_one(&mut pkt[0]));
        assert_eq!(pkt[0].as_ref(), CLEARTEXT);

        send.encrypt(&mut pkt);
        assert_eq!(pkt[0].len(), 38);
        let Ok(Message::TransportDataHeader(msg)) = Message::try_from(pkt[0].as_ref()) else {
            panic!("packet is not a valid TransportData message");
        };
        assert_eq!(msg.receiver_id, session);
        assert_eq!(u64::from(msg.nonce), 1);

        assert!(recv.decrypt_one(&mut pkt[0]));
        assert_eq!(pkt[0].as_ref(), CLEARTEXT);
    }

    #[test]
    fn session_timers() {
        let k: [u8; 32] = rand::random();
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now);
        let recv = ReceiveSession::new(k.into(), session, now);

        assert!(!send.stale(now));
        assert!(!send.stale(now + Duration::from_secs(100)));
        assert!(send.stale(now + Duration::from_secs(130)));
        assert!(send.stale(now + Duration::from_secs(250)));

        assert!(!send.expired(now));
        assert!(!send.expired(now + Duration::from_secs(100)));
        assert!(!send.expired(now + Duration::from_secs(130)));
        assert!(send.expired(now + Duration::from_secs(250)));

        assert!(!recv.expired(now));
        assert!(!recv.expired(now + Duration::from_secs(100)));
        assert!(!recv.expired(now + Duration::from_secs(130)));
        assert!(recv.expired(now + Duration::from_secs(250)));
    }

    // ---- ReplayFilter unit tests ----

    #[test]
    fn replay_filter_first_packet_accepted() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(0));
    }

    #[test]
    fn replay_filter_sequential_accepted() {
        let mut rf = ReplayFilter::new();
        for i in 0..200 {
            assert!(rf.check_and_update(i), "counter {i} should be accepted");
        }
    }

    #[test]
    fn replay_filter_duplicate_rejected() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(0));
        assert!(
            !rf.check_and_update(0),
            "duplicate counter 0 should be rejected"
        );
    }

    #[test]
    fn replay_filter_out_of_order_within_window() {
        let mut rf = ReplayFilter::new();
        // Receive 0, then 5, then go back and fill in 1..=4.
        assert!(rf.check_and_update(0));
        assert!(rf.check_and_update(5));
        for i in 1..=4 {
            assert!(
                rf.check_and_update(i),
                "counter {i} within window should be accepted"
            );
        }
        // Now all of 0..=5 have been seen; duplicates should fail.
        for i in 0..=5 {
            assert!(
                !rf.check_and_update(i),
                "duplicate counter {i} should be rejected"
            );
        }
    }

    #[test]
    fn replay_filter_out_of_order_outside_window() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(0));
        // Advance well past the window.
        assert!(rf.check_and_update(200));
        // Counter 0 is now outside the 128-bit window.
        assert!(
            !rf.check_and_update(0),
            "counter 0 too old, should be rejected"
        );
        // Counter 72 is also outside (200 - 72 = 128, which is >= WINDOW_SIZE).
        assert!(
            !rf.check_and_update(72),
            "counter 72 too old, should be rejected"
        );
        // Counter 73 is at the edge (200 - 73 = 127 < 128).
        assert!(
            rf.check_and_update(73),
            "counter 73 at edge should be accepted"
        );
    }

    #[test]
    fn replay_filter_window_boundary_exact() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(127));
        // Counter 0 is exactly at offset 127 (127 - 0 = 127), which is < 128.
        assert!(
            rf.check_and_update(0),
            "counter 0 at exact boundary should be accepted"
        );
        // Now duplicate of 0 should be rejected.
        assert!(!rf.check_and_update(0));
    }

    #[test]
    fn replay_filter_large_gap_clears_window() {
        let mut rf = ReplayFilter::new();
        for i in 0..10 {
            assert!(rf.check_and_update(i));
        }
        // Jump far ahead, clearing the entire window.
        assert!(rf.check_and_update(1000));
        // Everything before 1000 - 127 = 873 should be rejected.
        assert!(!rf.check_and_update(872));
        // 873 should be accepted (offset = 1000 - 873 = 127 < 128).
        assert!(rf.check_and_update(873));
    }

    #[test]
    fn replay_filter_counter_zero_first() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(0));
        assert!(!rf.check_and_update(0));
        assert!(rf.check_and_update(1));
    }

    #[test]
    fn replay_filter_nonzero_first() {
        // First packet doesn't have to be counter 0.
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(42));
        assert!(!rf.check_and_update(42));
        assert!(rf.check_and_update(43));
    }

    #[test]
    fn replay_filter_reverse_order() {
        let mut rf = ReplayFilter::new();
        // Receive highest first, then fill backwards within window.
        assert!(rf.check_and_update(127));
        for i in (0..127).rev() {
            assert!(
                rf.check_and_update(i),
                "counter {i} should be accepted in reverse"
            );
        }
        // All duplicates should fail.
        for i in 0..=127 {
            assert!(!rf.check_and_update(i), "duplicate {i} should be rejected");
        }
    }

    #[test]
    fn replay_filter_slide_then_old() {
        let mut rf = ReplayFilter::new();
        assert!(rf.check_and_update(0));
        assert!(rf.check_and_update(100));
        // 0 is still in window (offset 100, but window is 128).
        assert!(!rf.check_and_update(0), "counter 0 already seen");
        // Slide further to push 0 out.
        assert!(rf.check_and_update(129));
        // 0 is now outside window (129 - 0 = 129 >= 128).
        assert!(!rf.check_and_update(0), "counter 0 too old");
        // 1 is also outside (129 - 1 = 128 >= 128).
        assert!(!rf.check_and_update(1), "counter 1 too old");
        // 2 is at edge (129 - 2 = 127 < 128), and hasn't been seen.
        assert!(
            rf.check_and_update(2),
            "counter 2 at edge should be accepted"
        );
    }

    #[test]
    fn replay_filter_stress_window_full() {
        let mut rf = ReplayFilter::new();
        // Fill window completely with 0..=127.
        for i in 0..=127u64 {
            assert!(rf.check_and_update(i));
        }
        // Every single one should be rejected as duplicate.
        for i in 0..=127u64 {
            assert!(!rf.check_and_update(i), "duplicate {i} in full window");
        }
        // Next new counter should work.
        assert!(rf.check_and_update(128));
    }

    // ---- Session-level replay integration tests ----

    #[test]
    fn session_replay_rejected() {
        let k: [u8; 32] = rand::random();
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now);
        let recv = ReceiveSession::new(k.into(), session, now);

        const CLEARTEXT: &[u8] = b"hello replay";
        let mut pkt = [PacketMut::from(CLEARTEXT)];

        send.encrypt(&mut pkt);
        // Save a copy of the encrypted packet for replay.
        let replay_pkt = pkt[0].clone();

        // First decrypt: should succeed.
        assert!(recv.decrypt_one(&mut pkt[0]));
        assert_eq!(pkt[0].as_ref(), CLEARTEXT);

        // Replay the saved packet: should be rejected.
        let mut replayed = replay_pkt;
        assert!(
            !recv.decrypt_one(&mut replayed),
            "replayed packet must be rejected"
        );
    }

    #[test]
    fn session_out_of_order_accepted() {
        let k: [u8; 32] = rand::random();
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now);
        let recv = ReceiveSession::new(k.into(), session, now);

        const CLEARTEXT: &[u8] = b"ooo test";

        // Encrypt 3 packets: nonces 0, 1, 2.
        let mut pkt0 = [PacketMut::from(CLEARTEXT)];
        send.encrypt(&mut pkt0);
        let mut pkt1 = [PacketMut::from(CLEARTEXT)];
        send.encrypt(&mut pkt1);
        let mut pkt2 = [PacketMut::from(CLEARTEXT)];
        send.encrypt(&mut pkt2);

        // Decrypt in order 2, 0, 1 (out of order).
        assert!(recv.decrypt_one(&mut pkt2[0]), "pkt2 should be accepted");
        assert!(
            recv.decrypt_one(&mut pkt0[0]),
            "pkt0 out-of-order should be accepted"
        );
        assert!(
            recv.decrypt_one(&mut pkt1[0]),
            "pkt1 out-of-order should be accepted"
        );
    }

    #[test]
    fn session_old_packet_rejected_after_many() {
        let k: [u8; 32] = rand::random();
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now);
        let recv = ReceiveSession::new(k.into(), session, now);

        const CLEARTEXT: &[u8] = b"old pkt";

        // Encrypt packet 0 and save it.
        let mut pkt_old = [PacketMut::from(CLEARTEXT)];
        send.encrypt(&mut pkt_old);
        let saved = pkt_old[0].clone();

        // Decrypt packet 0.
        assert!(recv.decrypt_one(&mut pkt_old[0]));

        // Encrypt and decrypt 200 more packets to push nonce 0 out of window.
        for _ in 0..200 {
            let mut pkt = [PacketMut::from(CLEARTEXT)];
            send.encrypt(&mut pkt);
            assert!(recv.decrypt_one(&mut pkt[0]));
        }

        // Try replaying the saved packet 0: should be rejected (too old).
        let mut old = saved;
        assert!(
            !recv.decrypt_one(&mut old),
            "packet with nonce 0 should be rejected after 200 newer packets"
        );
    }
}
