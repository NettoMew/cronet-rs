// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/brutal_sender.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <optional>
#include <string>

#include "quiche/quic/core/congestion_control/bbr_sender.h"
#include "quiche/quic/core/congestion_control/rtt_stats.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/frames/quic_ack_frequency_frame.h"
#include "quiche/quic/core/frames/quic_frame.h"
#include "quiche/quic/core/frames/quic_ping_frame.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection_stats.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_sent_packet_manager.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_unacked_packet_map.h"

namespace quic::test {
namespace {

class ManualClock final : public QuicClock {
 public:
  ManualClock() : now_(QuicTime::Zero() + QuicTime::Delta::FromSeconds(1)) {}

  void Advance(QuicTime::Delta delta) { now_ = now_ + delta; }

  QuicTime ApproximateNow() const override { return now_; }
  QuicTime Now() const override { return now_; }
  QuicWallTime WallNow() const override {
    return QuicWallTime::FromUNIXMicroseconds(
        static_cast<uint64_t>((now_ - QuicTime::Zero()).ToMicroseconds()));
  }

 private:
  QuicTime now_;
};

class DeterministicRandom final : public QuicRandom {
 public:
  explicit DeterministicRandom(uint64_t seed) : state_(seed) {}

  void RandBytes(void* data, size_t len) override {
    InsecureRandBytes(data, len);
  }
  uint64_t RandUint64() override { return InsecureRandUint64(); }
  void InsecureRandBytes(void* data, size_t len) override {
    auto* bytes = static_cast<uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
      bytes[i] = static_cast<uint8_t>(InsecureRandUint64() & 0xff);
    }
  }
  uint64_t InsecureRandUint64() override {
    state_ = state_ * 6364136223846793005ULL + 1442695040888963407ULL;
    return state_;
  }

 private:
  uint64_t state_;
};

#define CHECK_TRUE(cond)                                                     \
  do {                                                                       \
    if (!(cond)) {                                                           \
      std::fprintf(stderr, "CHECK_TRUE failed at %s:%d: %s\n", __FILE__,     \
                   __LINE__, #cond);                                         \
      std::abort();                                                          \
    }                                                                        \
  } while (false)

#define CHECK_EQ_U64(actual, expected)                                       \
  do {                                                                       \
    const uint64_t a_ = static_cast<uint64_t>(actual);                       \
    const uint64_t e_ = static_cast<uint64_t>(expected);                     \
    if (a_ != e_) {                                                          \
      std::fprintf(stderr,                                                   \
                   "CHECK_EQ_U64 failed at %s:%d: %s (%llu) != %s (%llu)\n", \
                   __FILE__, __LINE__, #actual,                              \
                   static_cast<unsigned long long>(a_), #expected,           \
                   static_cast<unsigned long long>(e_));                     \
      std::abort();                                                          \
    }                                                                        \
  } while (false)

void SendDummyPacket(QuicSentPacketManager* spm,
                     uint64_t pn,
                     QuicByteCount bytes,
                     EncryptionLevel level,
                     QuicTime now) {
  SerializedPacket pkt(QuicPacketNumber(pn), PACKET_4BYTE_PACKET_NUMBER,
                       nullptr, static_cast<QuicPacketLength>(bytes), false,
                       false);
  pkt.encryption_level = level;
  pkt.retransmittable_frames.push_back(QuicFrame(QuicPingFrame(1)));
  spm->OnPacketSent(&pkt, now, NOT_RETRANSMISSION, HAS_RETRANSMITTABLE_DATA,
                    true, ECN_NOT_ECT);
}

void DeliverAckRange(QuicSentPacketManager* spm,
                     uint64_t start_pn,
                     uint64_t end_pn_inclusive,
                     QuicTime::Delta reported_ack_delay,
                     EncryptionLevel level,
                     uint64_t ack_pkt_num,
                     QuicTime now) {
  spm->OnAckFrameStart(QuicPacketNumber(end_pn_inclusive), reported_ack_delay,
                       now);
  spm->OnAckRange(QuicPacketNumber(start_pn),
                  QuicPacketNumber(end_pn_inclusive + 1));
  spm->OnAckFrameEnd(now, QuicPacketNumber(ack_pkt_num), level, std::nullopt);
}

// Drives a paced QuicSentPacketManager send/ACK loop over `duration` of
// simulated time and returns the achieved send rate in bytes/sec.
struct SimParams {
  uint64_t target_rate_bps = 1'500'000;
  QuicByteCount packet_size = 1250;
  QuicTime::Delta wire_rtt = QuicTime::Delta::FromMicroseconds(500);
  size_t ack_every_n_packets = 1;
  QuicTime::Delta peer_ack_timer = QuicTime::Delta::Zero();
  bool report_ack_delay = true;
  std::optional<uint64_t> peer_max_ack_delay_tp_ms = std::nullopt;
  QuicTime::Delta timer_tick = QuicTime::Delta::FromMicroseconds(100);
  QuicTime::Delta duration = QuicTime::Delta::FromSeconds(2);
};

struct SimResult {
  uint64_t total_bytes_sent = 0;
  double achieved_bps = 0.0;
  QuicByteCount steady_cwnd = 0;
  int64_t steady_srtt_us = 0;
  uint64_t cwnd_blocked_count = 0;
};

SimResult SimulateBrutalLink(const SimParams& p) {
  ManualClock clock;
  QuicConnectionStats stats;
  QuicSentPacketManager spm(Perspective::IS_CLIENT, &clock,
                            QuicRandom::GetInstance(), &stats, kCubicBytes);
  spm.EnableMultiplePacketNumberSpacesSupport();

  QuicConfig config;
  QuicTagVector client_opts;
  client_opts.push_back(kBRTL);
  config.SetClientConnectionOptions(client_opts);
  if (p.peer_max_ack_delay_tp_ms.has_value()) {
    TransportParameters tp;
    tp.perspective = Perspective::IS_SERVER;
    tp.max_ack_delay.set_value(*p.peer_max_ack_delay_tp_ms);
    std::string error_details;
    CHECK_TRUE(config.ProcessTransportParameters(tp, /*is_resumption=*/false,
                                                 &error_details) ==
               QUIC_NO_ERROR);
  }
  spm.SetFromConfig(config);

  uint64_t next_pn = 1;
  uint64_t next_ack_pn = 1;

  // Handshake packet establishes `min_rtt = wire_rtt` without delayed ACK
  // (RFC 9000 Section 13.2.1).
  SendDummyPacket(&spm, next_pn, p.packet_size, ENCRYPTION_INITIAL,
                  clock.Now());
  clock.Advance(p.wire_rtt);
  DeliverAckRange(&spm, next_pn, next_pn, QuicTime::Delta::Zero(),
                  ENCRYPTION_INITIAL, next_ack_pn++, clock.Now());
  ++next_pn;
  spm.SetHandshakeConfirmed();
  spm.SetBrutalSendRate(p.target_rate_bps);

  struct ArrivalEvent {
    QuicTime server_rx_time;
    uint64_t pn;
  };
  struct PendingAck {
    QuicTime client_rx_time;
    uint64_t start_pn;
    uint64_t end_pn;
    QuicTime::Delta reported_delay;
  };

  std::deque<ArrivalEvent> to_server;
  std::deque<PendingAck> to_client;
  uint64_t unacked_start_pn = 0;
  uint64_t unacked_end_pn = 0;
  size_t unacked_count = 0;
  QuicTime first_unacked_rx = QuicTime::Zero();
  QuicTime largest_unacked_rx = QuicTime::Zero();

  const QuicTime start_time = clock.Now();
  const QuicTime end_time = start_time + p.duration;
  QuicTime next_timer_wakeup = start_time;

  SimResult out;
  while (clock.Now() < end_time) {
    const QuicTime now = clock.Now();

    // 1. Server processes arrived client packets up to `now - wire_rtt / 2`.
    while (!to_server.empty() && to_server.front().server_rx_time <= now) {
      const ArrivalEvent ev = to_server.front();
      to_server.pop_front();
      if (unacked_count == 0) {
        unacked_start_pn = ev.pn;
        first_unacked_rx = ev.server_rx_time;
      }
      unacked_end_pn = ev.pn;
      largest_unacked_rx = ev.server_rx_time;
      ++unacked_count;

      if (unacked_count >= p.ack_every_n_packets &&
          p.peer_ack_timer.IsZero()) {
        to_client.push_back(PendingAck{
            ev.server_rx_time +
                QuicTime::Delta::FromMicroseconds(p.wire_rtt.ToMicroseconds() /
                                                  2),
            unacked_start_pn, unacked_end_pn, QuicTime::Delta::Zero()});
        unacked_count = 0;
      } else if (p.ack_every_n_packets > 1 &&
                 unacked_count >= p.ack_every_n_packets) {
        const QuicTime::Delta d = ev.server_rx_time - largest_unacked_rx;
        to_client.push_back(PendingAck{
            ev.server_rx_time +
                QuicTime::Delta::FromMicroseconds(p.wire_rtt.ToMicroseconds() /
                                                  2),
            unacked_start_pn, unacked_end_pn,
            p.report_ack_delay ? d : QuicTime::Delta::Zero()});
        unacked_count = 0;
      }
    }

    // 2. Server delayed-ACK timer fires when `first_unacked_rx + peer_ack_timer <= now`.
    if (unacked_count > 0 && !p.peer_ack_timer.IsZero() &&
        first_unacked_rx + p.peer_ack_timer <= now) {
      const QuicTime ack_tx = first_unacked_rx + p.peer_ack_timer;
      const QuicTime::Delta ack_delay = ack_tx - largest_unacked_rx;
      to_client.push_back(PendingAck{
          ack_tx + QuicTime::Delta::FromMicroseconds(
                       p.wire_rtt.ToMicroseconds() / 2),
          unacked_start_pn, unacked_end_pn,
          p.report_ack_delay ? ack_delay : QuicTime::Delta::Zero()});
      unacked_count = 0;
    }

    // 3. Client processes arrived ACKs (socket-read wakeup).
    bool ack_arrived = false;
    while (!to_client.empty() && to_client.front().client_rx_time <= now) {
      const PendingAck ack = to_client.front();
      to_client.pop_front();
      DeliverAckRange(&spm, ack.start_pn, ack.end_pn, ack.reported_delay,
                      ENCRYPTION_FORWARD_SECURE, next_ack_pn++, now);
      ack_arrived = true;
    }

    // 4. Client sends packets whenever woken by timer tick or incoming ACK.
    if (ack_arrived || now >= next_timer_wakeup) {
      while (true) {
        const QuicTime::Delta wait = spm.TimeUntilSend(now);
        if (wait.IsZero()) {
          SendDummyPacket(&spm, next_pn, p.packet_size,
                          ENCRYPTION_FORWARD_SECURE, now);
          to_server.push_back(ArrivalEvent{
              now + QuicTime::Delta::FromMicroseconds(
                        p.wire_rtt.ToMicroseconds() / 2),
              next_pn});
          ++next_pn;
          out.total_bytes_sent += p.packet_size;
          continue;
        }
        if (wait.IsInfinite()) {
          ++out.cwnd_blocked_count;
        }
        break;
      }
      while (next_timer_wakeup <= now) {
        next_timer_wakeup = next_timer_wakeup + p.timer_tick;
      }
    }

    // Advance clock to next interesting event (next 100us step or timer tick).
    clock.Advance(QuicTime::Delta::FromMicroseconds(100));
  }

  out.achieved_bps = static_cast<double>(out.total_bytes_sent) /
                     (static_cast<double>(p.duration.ToMicroseconds()) /
                      1'000'000.0);
  out.steady_cwnd = spm.GetCongestionWindowInBytes();
  out.steady_srtt_us = spm.GetRttStats()->smoothed_rtt().ToMicroseconds();
  return out;
}

void TestZeroRateMatchesBbrExactly() {
  ManualClock clock;
  RttStats brutal_rtt;
  RttStats bbr_rtt;
  QuicUnackedPacketMap brutal_unacked(Perspective::IS_CLIENT);
  QuicUnackedPacketMap bbr_unacked(Perspective::IS_CLIENT);
  QuicConnectionStats brutal_stats;
  QuicConnectionStats bbr_stats;
  DeterministicRandom brutal_rng(0x123456789abcdef0ULL);
  DeterministicRandom bbr_rng(0x123456789abcdef0ULL);

  BrutalSender brutal(clock.Now(), &brutal_rtt, &brutal_unacked, 32, 2000,
                      &brutal_rng, &brutal_stats);
  BbrSender bbr(clock.Now(), &bbr_rtt, &bbr_unacked, 32, 2000, &bbr_rng,
                &bbr_stats);

  CHECK_TRUE(brutal.GetCongestionControlType() == kBrutal);
  CHECK_EQ_U64(brutal.target_rate_bps(), 0);
  CHECK_EQ_U64(brutal.GetCongestionWindow(), bbr.GetCongestionWindow());
  CHECK_EQ_U64(brutal.PacingRate(0).ToBitsPerSecond(),
               bbr.PacingRate(0).ToBitsPerSecond());
  CHECK_TRUE(brutal.InSlowStart() == bbr.InSlowStart());

  QuicByteCount in_flight = 0;
  for (uint64_t pn = 1; pn <= 120; ++pn) {
    const QuicPacketNumber packet_number(pn);
    constexpr QuicByteCount kPktSize = 1350;
    SerializedPacket brutal_pkt(packet_number, PACKET_4BYTE_PACKET_NUMBER,
                                nullptr, kPktSize, false, false);
    SerializedPacket bbr_pkt(packet_number, PACKET_4BYTE_PACKET_NUMBER, nullptr,
                             kPktSize, false, false);
    brutal_unacked.AddSentPacket(&brutal_pkt, NOT_RETRANSMISSION, clock.Now(),
                                 true, true, ECN_NOT_ECT);
    bbr_unacked.AddSentPacket(&bbr_pkt, NOT_RETRANSMISSION, clock.Now(), true,
                              true, ECN_NOT_ECT);

    brutal.OnPacketSent(clock.Now(), in_flight, packet_number, kPktSize,
                        HAS_RETRANSMITTABLE_DATA);
    bbr.OnPacketSent(clock.Now(), in_flight, packet_number, kPktSize,
                     HAS_RETRANSMITTABLE_DATA);
    in_flight += kPktSize;

    clock.Advance(QuicTime::Delta::FromMilliseconds(2));
    const QuicTime::Delta rtt =
        QuicTime::Delta::FromMilliseconds(25 + (pn % 10));
    brutal_rtt.UpdateRtt(rtt, QuicTime::Delta::Zero(), clock.Now());
    bbr_rtt.UpdateRtt(rtt, QuicTime::Delta::Zero(), clock.Now());

    AckedPacketVector acked;
    LostPacketVector lost;
    if (pn % 17 == 0) {
      lost.emplace_back(packet_number, kPktSize);
      brutal_unacked.RemoveFromInFlight(packet_number);
      bbr_unacked.RemoveFromInFlight(packet_number);
    } else {
      acked.emplace_back(packet_number, kPktSize, clock.Now());
      brutal_unacked.RemoveFromInFlight(packet_number);
      bbr_unacked.RemoveFromInFlight(packet_number);
    }
    brutal.OnCongestionEvent(true, in_flight, clock.Now(), acked, lost, 0, 0);
    bbr.OnCongestionEvent(true, in_flight, clock.Now(), acked, lost, 0, 0);
    in_flight -= kPktSize;

    CHECK_EQ_U64(brutal.GetCongestionWindow(), bbr.GetCongestionWindow());
    CHECK_EQ_U64(brutal.PacingRate(in_flight).ToBitsPerSecond(),
                 bbr.PacingRate(in_flight).ToBitsPerSecond());
    CHECK_EQ_U64(brutal.BandwidthEstimate().ToBitsPerSecond(),
                 bbr.BandwidthEstimate().ToBitsPerSecond());
    CHECK_TRUE(brutal.InSlowStart() == bbr.InSlowStart());
    CHECK_TRUE(brutal.InRecovery() == bbr.InRecovery());
    CHECK_TRUE(brutal.CanSend(in_flight) == bbr.CanSend(in_flight));
  }

  // Enabling Brutal overrides pacing/cwnd; setting rate back to 0 restores BBR.
  brutal.SetTargetRateBps(20'000'000);
  CHECK_EQ_U64(brutal.PacingRate(0).ToBytesPerSecond(), 20'000'000);
  CHECK_TRUE(!brutal.InSlowStart());
  brutal.SetTargetRateBps(0);
  CHECK_EQ_U64(brutal.GetCongestionWindow(), bbr.GetCongestionWindow());
  CHECK_EQ_U64(brutal.PacingRate(0).ToBitsPerSecond(),
               bbr.PacingRate(0).ToBitsPerSecond());
}

void TestLossCompensationAndWindowFormula() {
  ManualClock clock;
  RttStats rtt_stats;
  QuicUnackedPacketMap unacked(Perspective::IS_CLIENT);
  QuicConnectionStats stats;
  BrutalSender sender(clock.Now(), &rtt_stats, &unacked, 32, 2000,
                      QuicRandom::GetInstance(), &stats);

  constexpr uint64_t kBaseRateBps = 12'500'000;  // 100 Mbps
  sender.SetTargetRateBps(kBaseRateBps);
  rtt_stats.UpdateRtt(QuicTime::Delta::FromMilliseconds(40),
                      QuicTime::Delta::Zero(), clock.Now());

  // Effective ACK-loop RTT = 40ms + 25ms (kDefaultPeerDelayedAckTimeMs) = 65ms;
  // cwnd = 2 * 12,500,000 * 0.065 = 1,625,000 B.
  CHECK_EQ_U64(sender.PacingRate(0).ToBytesPerSecond(), kBaseRateBps);
  CHECK_EQ_U64(sender.GetCongestionWindow(), 1'625'000);

  // 49 samples (40 acked + 9 lost) stays below the 50-sample threshold.
  uint64_t next_pn = 1;
  auto emit_outcomes = [&](size_t ack_count, size_t loss_count) {
    AckedPacketVector acked;
    LostPacketVector lost;
    for (size_t i = 0; i < ack_count; ++i) {
      acked.emplace_back(QuicPacketNumber(next_pn++), 1200, clock.Now());
    }
    for (size_t i = 0; i < loss_count; ++i) {
      lost.emplace_back(QuicPacketNumber(next_pn++), 1200);
    }
    sender.OnCongestionEvent(false, 0, clock.Now(), acked, lost, 0, 0);
  };

  emit_outcomes(40, 9);
  CHECK_EQ_U64(sender.CompensatedRateBps(), kBaseRateBps);
  CHECK_EQ_U64(sender.GetCongestionWindow(), 1'625'000);

  // 50th sample is lost (40 acked + 10 lost => ack_rate = 0.8 => 1.25x).
  emit_outcomes(0, 1);
  CHECK_EQ_U64(sender.CompensatedRateBps(), 15'625'000);
  CHECK_EQ_U64(sender.GetCongestionWindow(), 2'031'250);
  CHECK_EQ_U64(sender.PacingRate(0).ToBytesPerSecond(), 15'625'000);

  // RTO and losses never shrink Brutal's cwnd.
  sender.OnRetransmissionTimeout(true);
  CHECK_EQ_U64(sender.GetCongestionWindow(), 2'031'250);
  CHECK_TRUE(!sender.InRecovery());

  // 50% loss in a fresh 5-second window is floored at ack_rate = 0.8 (1.25x).
  clock.Advance(QuicTime::Delta::FromSeconds(6));
  emit_outcomes(30, 30);
  CHECK_EQ_U64(sender.CompensatedRateBps(), 15'625'000);
  CHECK_EQ_U64(sender.GetCongestionWindow(), 2'031'250);

  // 10% loss in a fresh window (90 acked + 10 lost => ack_rate = 0.9).
  clock.Advance(QuicTime::Delta::FromSeconds(6));
  emit_outcomes(90, 10);
  CHECK_EQ_U64(sender.CompensatedRateBps(), 13'888'888);

  // After the 5-second window advances past the losses, ack_rate returns to 1.
  clock.Advance(QuicTime::Delta::FromSeconds(6));
  emit_outcomes(60, 0);
  CHECK_EQ_U64(sender.CompensatedRateBps(), kBaseRateBps);
  CHECK_EQ_U64(sender.GetCongestionWindow(), 1'625'000);

  // Sub-millisecond srtt floors at 1 ms + 25 ms = 26 ms (52 ms scaled), and
  // tiny rates floor at 10 * kDefaultTCPMSS.
  RttStats fast_rtt;
  fast_rtt.UpdateRtt(QuicTime::Delta::FromMicroseconds(200),
                     QuicTime::Delta::Zero(), clock.Now());
  BrutalSender sub_ms(clock.Now(), &fast_rtt, &unacked, 32, 2000,
                      QuicRandom::GetInstance(), &stats);
  sub_ms.SetTargetRateBps(10'000'000);
  CHECK_EQ_U64(sub_ms.GetCongestionWindow(), 520'000);

  sub_ms.SetTargetRateBps(100);
  CHECK_EQ_U64(sub_ms.GetCongestionWindow(), 10 * kDefaultTCPMSS);
}

void TestSentPacketManagerBrtlOptionAndMigrationCache() {
  ManualClock clock;
  QuicConnectionStats stats;
  QuicSentPacketManager client_spm(Perspective::IS_CLIENT, &clock,
                                   QuicRandom::GetInstance(), &stats,
                                   kCubicBytes);
  client_spm.EnableMultiplePacketNumberSpacesSupport();

  QuicConfig config;
  QuicTagVector client_opts;
  client_opts.push_back(kBRTL);
  config.SetClientConnectionOptions(client_opts);

  TransportParameters tp;
  tp.perspective = Perspective::IS_SERVER;
  tp.max_ack_delay.set_value(60);
  std::string err;
  CHECK_TRUE(config.ProcessTransportParameters(tp, /*is_resumption=*/false,
                                               &err) == QUIC_NO_ERROR);
  client_spm.SetFromConfig(config);

  CHECK_TRUE(client_spm.GetSendAlgorithm()->GetCongestionControlType() ==
             kBrutal);
  CHECK_EQ_U64(client_spm.brutal_send_rate_bps(), 0);
  CHECK_EQ_U64(static_cast<const BrutalSender*>(client_spm.GetSendAlgorithm())
                   ->peer_max_ack_delay()
                   .ToMilliseconds(),
               60);

  client_spm.SetBrutalSendRate(8'000'000);
  CHECK_EQ_U64(client_spm.brutal_send_rate_bps(), 8'000'000);
  CHECK_EQ_U64(client_spm.GetSendAlgorithm()->PacingRate(0).ToBytesPerSecond(),
               8'000'000);
  // Initial srtt = 100ms, peer_max_ack_delay = 60ms => 2 * 8MB/s * 160ms.
  CHECK_EQ_U64(client_spm.GetCongestionWindowInBytes(), 2'560'000);

  // Sending and ACKing an ACK_FREQUENCY frame updates BrutalSender's
  // peer_max_ack_delay through the single synchronization helper.
  {
    SerializedPacket af_pkt(QuicPacketNumber(1), PACKET_4BYTE_PACKET_NUMBER,
                            nullptr, 100, false, false);
    af_pkt.encryption_level = ENCRYPTION_FORWARD_SECURE;
    af_pkt.has_ack_frequency = true;
    af_pkt.retransmittable_frames.push_back(QuicFrame(new QuicAckFrequencyFrame(
        1, /*sequence_number=*/1, /*ack_eliciting_threshold=*/10,
        QuicTime::Delta::FromMilliseconds(80))));
    client_spm.OnPacketSent(&af_pkt, clock.Now(), NOT_RETRANSMISSION,
                            HAS_RETRANSMITTABLE_DATA, true, ECN_NOT_ECT);
  }
  CHECK_EQ_U64(static_cast<const BrutalSender*>(client_spm.GetSendAlgorithm())
                   ->peer_max_ack_delay()
                   .ToMilliseconds(),
               80);

  {
    SerializedPacket af_pkt2(QuicPacketNumber(2), PACKET_4BYTE_PACKET_NUMBER,
                             nullptr, 100, false, false);
    af_pkt2.encryption_level = ENCRYPTION_FORWARD_SECURE;
    af_pkt2.has_ack_frequency = true;
    af_pkt2.retransmittable_frames.push_back(
        QuicFrame(new QuicAckFrequencyFrame(
            2, /*sequence_number=*/2, /*ack_eliciting_threshold=*/4,
            QuicTime::Delta::FromMilliseconds(40))));
    client_spm.OnPacketSent(&af_pkt2, clock.Now(), NOT_RETRANSMISSION,
                            HAS_RETRANSMITTABLE_DATA, true, ECN_NOT_ECT);
  }
  clock.Advance(QuicTime::Delta::FromMilliseconds(10));
  DeliverAckRange(&client_spm, 1, 2, QuicTime::Delta::Zero(),
                  ENCRYPTION_FORWARD_SECURE, 1, clock.Now());
  CHECK_EQ_U64(static_cast<const BrutalSender*>(client_spm.GetSendAlgorithm())
                   ->peer_max_ack_delay()
                   .ToMilliseconds(),
               40);

  // Connection migration with send-algorithm reset must preserve both the rate
  // and the synchronized peer_max_ack_delay.
  auto old_alg = client_spm.OnConnectionMigration(/*reset_send_algorithm=*/true);
  CHECK_TRUE(old_alg != nullptr);
  CHECK_TRUE(client_spm.GetSendAlgorithm()->GetCongestionControlType() ==
             kBrutal);
  CHECK_EQ_U64(client_spm.GetSendAlgorithm()->PacingRate(0).ToBytesPerSecond(),
               8'000'000);
  CHECK_EQ_U64(static_cast<const BrutalSender*>(client_spm.GetSendAlgorithm())
                   ->peer_max_ack_delay()
                   .ToMilliseconds(),
               40);

  // Server-side SentPacketManager ignores client-only kBRTL.
  QuicSentPacketManager server_spm(Perspective::IS_SERVER, &clock,
                                   QuicRandom::GetInstance(), &stats,
                                   kCubicBytes);
  server_spm.SetFromConfig(config);
  CHECK_TRUE(server_spm.GetSendAlgorithm()->GetCongestionControlType() ==
             kCubicBytes);
}

void TestReportedAckDelay15MsWindowAndThroughput() {
  SimParams params;
  params.target_rate_bps = 1'500'000;
  params.wire_rtt = QuicTime::Delta::FromMicroseconds(500);
  params.ack_every_n_packets = 1000;  // Force delayed-ACK timer on every batch.
  params.peer_ack_timer = QuicTime::Delta::FromMilliseconds(15);
  params.report_ack_delay = true;

  const SimResult res = SimulateBrutalLink(params);
  // RttStats subtracts reported ack_delay, keeping srtt at ~500us (< 1ms),
  // while Brutal's window covers 2 * 1.5MB/s * (1ms + 25ms) = 78,000 B.
  CHECK_TRUE(res.steady_srtt_us <= 1000);
  CHECK_EQ_U64(res.steady_cwnd, 78'000);
  CHECK_EQ_U64(res.cwnd_blocked_count, 0);
  CHECK_TRUE(res.achieved_bps >= 1'470'000.0 &&
             res.achieved_bps <= 1'530'000.0);
}

void TestAckEvery10PacketsWindowAndThroughput() {
  // 1. Standard 1.5 MB/s rate with 1-in-10 ACK decimation (20ms fallback).
  SimParams medium;
  medium.target_rate_bps = 1'500'000;
  medium.wire_rtt = QuicTime::Delta::FromMicroseconds(200);
  medium.ack_every_n_packets = 10;
  medium.peer_ack_timer = QuicTime::Delta::FromMilliseconds(20);
  medium.report_ack_delay = true;

  const SimResult med_res = SimulateBrutalLink(medium);
  CHECK_EQ_U64(med_res.steady_cwnd, 78'000);
  CHECK_EQ_U64(med_res.cwnd_blocked_count, 0);
  CHECK_TRUE(med_res.achieved_bps >= 1'470'000.0 &&
             med_res.achieved_bps <= 1'530'000.0);

  // 2. Low 200 KB/s rate where `2 * rate * 26ms = 10,400 B` would sit below
  //    10 packets without the `10 * kDefaultTCPMSS = 14,600 B` floor.
  SimParams low;
  low.target_rate_bps = 200'000;
  low.wire_rtt = QuicTime::Delta::FromMicroseconds(200);
  low.ack_every_n_packets = 10;
  low.peer_ack_timer = QuicTime::Delta::FromMilliseconds(20);
  low.report_ack_delay = true;

  const SimResult low_res = SimulateBrutalLink(low);
  CHECK_EQ_U64(low_res.steady_cwnd, 10 * kDefaultTCPMSS);
  CHECK_EQ_U64(low_res.cwnd_blocked_count, 0);
  CHECK_TRUE(low_res.achieved_bps >= 195'000.0 &&
             low_res.achieved_bps <= 205'000.0);
}

void TestZeroPeerMaxAckDelayAndCoarseTimerThroughput() {
  SimParams params;
  params.target_rate_bps = 1'500'000;
  params.wire_rtt = QuicTime::Delta::FromMicroseconds(300);
  params.ack_every_n_packets = 1;
  params.peer_ack_timer = QuicTime::Delta::Zero();
  params.peer_max_ack_delay_tp_ms = 0;
  // Simulate 15.625ms (64 Hz) OS timer granularity.
  params.timer_tick = QuicTime::Delta::FromMicroseconds(15'625);

  const SimResult res = SimulateBrutalLink(params);
  // Even when peer advertises max_ack_delay = 0, Brutal floors the ACK-delay
  // term at kDefaultPeerDelayedAckTimeMs (25ms), giving cwnd = 78,000 B so
  // 15.625ms timer catch-up bursts (~23.4 KB) never hit cwnd or wipe credit.
  CHECK_EQ_U64(res.steady_cwnd, 78'000);
  CHECK_EQ_U64(res.cwnd_blocked_count, 0);
  CHECK_TRUE(res.achieved_bps >= 1'460'000.0 &&
             res.achieved_bps <= 1'540'000.0);
}

}  // namespace
}  // namespace quic::test

int main() {
  quic::test::TestZeroRateMatchesBbrExactly();
  quic::test::TestLossCompensationAndWindowFormula();
  quic::test::TestSentPacketManagerBrtlOptionAndMigrationCache();
  quic::test::TestReportedAckDelay15MsWindowAndThroughput();
  quic::test::TestAckEvery10PacketsWindowAndThroughput();
  quic::test::TestZeroPeerMaxAckDelayAndCoarseTimerThroughput();
  std::printf("PASS brutal_sender_test (6 suites)\n");
  return 0;
}
