// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_CONGESTION_CONTROL_BRUTAL_SENDER_H_
#define QUICHE_QUIC_CORE_CONGESTION_CONTROL_BRUTAL_SENDER_H_

#include <array>
#include <cstdint>
#include <string>

#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/quic/core/congestion_control/bbr_sender.h"
#include "quiche/quic/core/congestion_control/rtt_stats.h"
#include "quiche/quic/core/congestion_control/send_algorithm_interface.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection_stats.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_tag.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_unacked_packet_map.h"

namespace quic {

// QUIC Brutal congestion control sender.
//
// Until a non-zero target send rate is configured via SetTargetRateBps(), all
// congestion-control decisions delegate directly to an embedded BbrSender so
// unconfigured connections behave identically to BBR. Once a target rate (in
// bytes per second) is set, the sender paces at `rate / ack_rate` using a
// 5-second sliding window of acknowledged vs. lost packet counts (requiring at
// least 50 samples before compensating and flooring `ack_rate` at 0.8, capping
// loss compensation at 1.25x) and sizes its congestion window to
// `max(4 * kDefaultTCPMSS, compensated_rate * max(srtt, 1ms) * 2)`.
class QUICHE_EXPORT BrutalSender final : public SendAlgorithmInterface {
 public:
  static constexpr size_t kAckRateWindowSeconds = 5;
  static constexpr uint64_t kMinAckRateSamples = 50;
  static constexpr double kMinAckRate = 0.8;
  static constexpr uint64_t kCwndGain = 2;
  static constexpr QuicPacketCount kMinCongestionWindowPackets = 4;
  static constexpr QuicByteCount kMinCongestionWindowBytes =
      kMinCongestionWindowPackets * kDefaultTCPMSS;
  static constexpr int64_t kMinRttUs = 1000;
  static constexpr int64_t kMaxRttUs = 60'000'000;
  static constexpr uint64_t kMaxTargetRateBps = 125'000'000'000ULL;

  BrutalSender(QuicTime now,
               const RttStats* rtt_stats,
               const QuicUnackedPacketMap* unacked_packets,
               QuicPacketCount initial_tcp_congestion_window,
               QuicPacketCount max_tcp_congestion_window,
               QuicRandom* random,
               QuicConnectionStats* stats);
  BrutalSender(const BrutalSender&) = delete;
  BrutalSender& operator=(const BrutalSender&) = delete;
  ~BrutalSender() override;

  // Sets the target application send rate in bytes per second. Passing 0
  // disables fixed-rate sending and delegates decisions back to BbrSender.
  void SetTargetRateBps(uint64_t bytes_per_second);
  uint64_t target_rate_bps() const { return target_rate_bps_; }
  double ack_rate() const { return ack_rate_; }
  uint64_t CompensatedRateBps() const;

  // SendAlgorithmInterface implementation.
  void SetFromConfig(const QuicConfig& config,
                     Perspective perspective) override;
  void ApplyConnectionOptions(const QuicTagVector& connection_options) override;
  void SetInitialCongestionWindowInPackets(QuicPacketCount packets) override;
  void SetApplicationDrivenPacingRate(
      QuicBandwidth application_bandwidth_target) override;
  void OnCongestionEvent(bool rtt_updated,
                         QuicByteCount prior_in_flight,
                         QuicTime event_time,
                         const AckedPacketVector& acked_packets,
                         const LostPacketVector& lost_packets,
                         QuicPacketCount num_ect,
                         QuicPacketCount num_ce) override;
  void OnPacketSent(QuicTime sent_time,
                    QuicByteCount bytes_in_flight,
                    QuicPacketNumber packet_number,
                    QuicByteCount bytes,
                    HasRetransmittableData is_retransmittable) override;
  void OnPacketNeutered(QuicPacketNumber packet_number) override;
  void OnRetransmissionTimeout(bool packets_retransmitted) override;
  void OnConnectionMigration() override;
  bool CanSend(QuicByteCount bytes_in_flight) override;
  QuicBandwidth PacingRate(QuicByteCount bytes_in_flight) const override;
  QuicBandwidth BandwidthEstimate() const override;
  bool HasGoodBandwidthEstimateForResumption() const override;
  QuicByteCount GetCongestionWindow() const override;
  bool InSlowStart() const override;
  bool InRecovery() const override;
  QuicByteCount GetSlowStartThreshold() const override;
  CongestionControlType GetCongestionControlType() const override;
  void AdjustNetworkParameters(const NetworkParams& params) override;
  std::string GetDebugState() const override;
  void OnApplicationLimited(QuicByteCount bytes_in_flight) override;
  void PopulateConnectionStats(QuicConnectionStats* stats) const override;
  bool EnableECT0() override;
  bool EnableECT1() override;
  void ReduceMemoryUsage() override;

 private:
  struct PacketSlot {
    uint64_t second = 0;
    uint64_t acked = 0;
    uint64_t lost = 0;
    bool active = false;
  };

  void RecordPacketOutcomes(QuicTime event_time,
                            uint64_t acked,
                            uint64_t lost);
  void UpdateAckRate(uint64_t current_second);
  QuicByteCount CalculateCongestionWindow() const;

  const RttStats* rtt_stats_;
  BbrSender fallback_;
  uint64_t target_rate_bps_ = 0;
  QuicTime origin_ = QuicTime::Zero();
  std::array<PacketSlot, kAckRateWindowSeconds> slots_{};
  double ack_rate_ = 1.0;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_CONGESTION_CONTROL_BRUTAL_SENDER_H_
