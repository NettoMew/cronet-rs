// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/brutal_sender.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "quiche/quic/core/congestion_control/bbr_sender.h"
#include "quiche/quic/core/congestion_control/rtt_stats.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/quic_random.h"
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

  // BDP = 12,500,000 * 0.040 = 500,000 B; gain = 2.0x => 1,000,000 B.
  CHECK_EQ_U64(sender.PacingRate(0).ToBytesPerSecond(), kBaseRateBps);
  CHECK_EQ_U64(sender.GetCongestionWindow(), 1'000'000);

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
  CHECK_EQ_U64(sender.GetCongestionWindow(), 1'000'000);

  // 50th sample is lost (40 acked + 10 lost => ack_rate = 0.8 => 1.25x).
  emit_outcomes(0, 1);
  CHECK_EQ_U64(sender.CompensatedRateBps(), 15'625'000);
  CHECK_EQ_U64(sender.GetCongestionWindow(), 1'250'000);
  CHECK_EQ_U64(sender.PacingRate(0).ToBytesPerSecond(), 15'625'000);

  // RTO and losses never shrink Brutal's cwnd.
  sender.OnRetransmissionTimeout(true);
  CHECK_EQ_U64(sender.GetCongestionWindow(), 1'250'000);
  CHECK_TRUE(!sender.InRecovery());

  // 50% loss in a fresh 5-second window is floored at ack_rate = 0.8 (1.25x).
  clock.Advance(QuicTime::Delta::FromSeconds(6));
  emit_outcomes(30, 30);
  CHECK_EQ_U64(sender.CompensatedRateBps(), 15'625'000);
  CHECK_EQ_U64(sender.GetCongestionWindow(), 1'250'000);

  // 10% loss in a fresh window (90 acked + 10 lost => ack_rate = 0.9).
  clock.Advance(QuicTime::Delta::FromSeconds(6));
  emit_outcomes(90, 10);
  CHECK_EQ_U64(sender.CompensatedRateBps(), 13'888'888);

  // After the 5-second window advances past the losses, ack_rate returns to 1.
  clock.Advance(QuicTime::Delta::FromSeconds(6));
  emit_outcomes(60, 0);
  CHECK_EQ_U64(sender.CompensatedRateBps(), kBaseRateBps);
  CHECK_EQ_U64(sender.GetCongestionWindow(), 1'000'000);

  // Sub-millisecond RTT floors at 1 ms, and tiny rates floor at 4 * MSS.
  RttStats fast_rtt;
  fast_rtt.UpdateRtt(QuicTime::Delta::FromMicroseconds(200),
                     QuicTime::Delta::Zero(), clock.Now());
  BrutalSender sub_ms(clock.Now(), &fast_rtt, &unacked, 32, 2000,
                      QuicRandom::GetInstance(), &stats);
  sub_ms.SetTargetRateBps(10'000'000);
  CHECK_EQ_U64(sub_ms.GetCongestionWindow(), 20'000);

  sub_ms.SetTargetRateBps(1'000);
  CHECK_EQ_U64(sub_ms.GetCongestionWindow(), 4 * kDefaultTCPMSS);
}

void TestSentPacketManagerBrtlOptionAndMigrationCache() {
  ManualClock clock;
  QuicConnectionStats stats;
  QuicSentPacketManager client_spm(Perspective::IS_CLIENT, &clock,
                                   QuicRandom::GetInstance(), &stats,
                                   kCubicBytes);
  QuicConfig config;
  QuicTagVector client_opts;
  client_opts.push_back(kBRTL);
  config.SetClientConnectionOptions(client_opts);
  client_spm.SetFromConfig(config);

  CHECK_TRUE(client_spm.GetSendAlgorithm()->GetCongestionControlType() ==
             kBrutal);
  CHECK_EQ_U64(client_spm.brutal_send_rate_bps(), 0);

  client_spm.SetBrutalSendRate(8'000'000);
  CHECK_EQ_U64(client_spm.brutal_send_rate_bps(), 8'000'000);
  CHECK_EQ_U64(client_spm.GetSendAlgorithm()->PacingRate(0).ToBytesPerSecond(),
               8'000'000);

  // Connection migration with send-algorithm reset must preserve the rate.
  auto old_alg = client_spm.OnConnectionMigration(/*reset_send_algorithm=*/true);
  CHECK_TRUE(old_alg != nullptr);
  CHECK_TRUE(client_spm.GetSendAlgorithm()->GetCongestionControlType() ==
             kBrutal);
  CHECK_EQ_U64(client_spm.GetSendAlgorithm()->PacingRate(0).ToBytesPerSecond(),
               8'000'000);

  // Server-side SentPacketManager ignores client-only kBRTL.
  QuicSentPacketManager server_spm(Perspective::IS_SERVER, &clock,
                                   QuicRandom::GetInstance(), &stats,
                                   kCubicBytes);
  server_spm.SetFromConfig(config);
  CHECK_TRUE(server_spm.GetSendAlgorithm()->GetCongestionControlType() ==
             kCubicBytes);
}

}  // namespace
}  // namespace quic::test

int main() {
  quic::test::TestZeroRateMatchesBbrExactly();
  quic::test::TestLossCompensationAndWindowFormula();
  quic::test::TestSentPacketManagerBrtlOptionAndMigrationCache();
  std::printf("PASS brutal_sender_test (3 suites)\n");
  return 0;
}
