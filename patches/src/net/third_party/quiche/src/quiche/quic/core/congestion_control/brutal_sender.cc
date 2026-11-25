// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/brutal_sender.h"

#include <algorithm>
#include <sstream>
#include <string>

#include "quiche/quic/core/quic_constants.h"

namespace quic {

BrutalSender::BrutalSender(QuicTime now,
                           const RttStats* rtt_stats,
                           const QuicUnackedPacketMap* unacked_packets,
                           QuicPacketCount initial_tcp_congestion_window,
                           QuicPacketCount max_tcp_congestion_window,
                           QuicRandom* random,
                           QuicConnectionStats* stats)
    : rtt_stats_(rtt_stats),
      fallback_(now,
                rtt_stats,
                unacked_packets,
                initial_tcp_congestion_window,
                max_tcp_congestion_window,
                random,
                stats) {}

BrutalSender::~BrutalSender() = default;

void BrutalSender::SetTargetRateBps(uint64_t bytes_per_second) {
  const uint64_t clamped = std::min(bytes_per_second, kMaxTargetRateBps);
  if (clamped == 0 || target_rate_bps_ == 0) {
    slots_.fill(PacketSlot{});
    origin_ = QuicTime::Zero();
    ack_rate_ = 1.0;
  }
  target_rate_bps_ = clamped;
}

void BrutalSender::SetPeerMaxAckDelay(QuicTime::Delta peer_max_ack_delay) {
  if (peer_max_ack_delay < QuicTime::Delta::Zero() ||
      peer_max_ack_delay.IsInfinite()) {
    peer_max_ack_delay_ = QuicTime::Delta::Zero();
    return;
  }
  peer_max_ack_delay_ = peer_max_ack_delay;
}

uint64_t BrutalSender::CompensatedRateBps() const {
  if (target_rate_bps_ == 0) {
    return 0;
  }
  const double clamped_ack_rate = std::clamp(ack_rate_, kMinAckRate, 1.0);
  const double scaled =
      static_cast<double>(target_rate_bps_) / clamped_ack_rate;
  if (scaled >= static_cast<double>(kMaxTargetRateBps)) {
    return kMaxTargetRateBps;
  }
  return std::max<uint64_t>(1, static_cast<uint64_t>(scaled));
}

void BrutalSender::SetFromConfig(const QuicConfig& config,
                                 Perspective perspective) {
  fallback_.SetFromConfig(config, perspective);
}

void BrutalSender::ApplyConnectionOptions(
    const QuicTagVector& connection_options) {
  fallback_.ApplyConnectionOptions(connection_options);
}

void BrutalSender::SetInitialCongestionWindowInPackets(
    QuicPacketCount packets) {
  fallback_.SetInitialCongestionWindowInPackets(packets);
}

void BrutalSender::SetApplicationDrivenPacingRate(
    QuicBandwidth application_bandwidth_target) {
  fallback_.SetApplicationDrivenPacingRate(application_bandwidth_target);
}

void BrutalSender::OnCongestionEvent(bool rtt_updated,
                                     QuicByteCount prior_in_flight,
                                     QuicTime event_time,
                                     const AckedPacketVector& acked_packets,
                                     const LostPacketVector& lost_packets,
                                     QuicPacketCount num_ect,
                                     QuicPacketCount num_ce) {
  if (target_rate_bps_ > 0 && event_time.IsInitialized()) {
    uint64_t acked = 0;
    for (const AckedPacket& packet : acked_packets) {
      if (packet.bytes_acked > 0) {
        ++acked;
      }
    }
    const uint64_t lost = lost_packets.size();
    if (acked > 0 || lost > 0) {
      RecordPacketOutcomes(event_time, acked, lost);
    }
  }
  fallback_.OnCongestionEvent(rtt_updated, prior_in_flight, event_time,
                              acked_packets, lost_packets, num_ect, num_ce);
}

void BrutalSender::OnPacketSent(QuicTime sent_time,
                                QuicByteCount bytes_in_flight,
                                QuicPacketNumber packet_number,
                                QuicByteCount bytes,
                                HasRetransmittableData is_retransmittable) {
  fallback_.OnPacketSent(sent_time, bytes_in_flight, packet_number, bytes,
                         is_retransmittable);
}

void BrutalSender::OnPacketNeutered(QuicPacketNumber packet_number) {
  fallback_.OnPacketNeutered(packet_number);
}

void BrutalSender::OnRetransmissionTimeout(bool packets_retransmitted) {
  fallback_.OnRetransmissionTimeout(packets_retransmitted);
}

void BrutalSender::OnConnectionMigration() {
  slots_.fill(PacketSlot{});
  origin_ = QuicTime::Zero();
  ack_rate_ = 1.0;
  fallback_.OnConnectionMigration();
}

bool BrutalSender::CanSend(QuicByteCount bytes_in_flight) {
  if (target_rate_bps_ == 0) {
    return fallback_.CanSend(bytes_in_flight);
  }
  return bytes_in_flight < GetCongestionWindow();
}

QuicBandwidth BrutalSender::PacingRate(QuicByteCount bytes_in_flight) const {
  if (target_rate_bps_ == 0) {
    return fallback_.PacingRate(bytes_in_flight);
  }
  return QuicBandwidth::FromBytesPerSecond(
      static_cast<int64_t>(CompensatedRateBps()));
}

QuicBandwidth BrutalSender::BandwidthEstimate() const {
  if (target_rate_bps_ == 0) {
    return fallback_.BandwidthEstimate();
  }
  return QuicBandwidth::FromBytesPerSecond(
      static_cast<int64_t>(CompensatedRateBps()));
}

bool BrutalSender::HasGoodBandwidthEstimateForResumption() const {
  if (target_rate_bps_ == 0) {
    return fallback_.HasGoodBandwidthEstimateForResumption();
  }
  return false;
}

QuicByteCount BrutalSender::GetCongestionWindow() const {
  if (target_rate_bps_ == 0) {
    return fallback_.GetCongestionWindow();
  }
  return CalculateCongestionWindow();
}

bool BrutalSender::InSlowStart() const {
  if (target_rate_bps_ == 0) {
    return fallback_.InSlowStart();
  }
  return false;
}

bool BrutalSender::InRecovery() const {
  if (target_rate_bps_ == 0) {
    return fallback_.InRecovery();
  }
  return false;
}

QuicByteCount BrutalSender::GetSlowStartThreshold() const {
  if (target_rate_bps_ == 0) {
    return fallback_.GetSlowStartThreshold();
  }
  return 0;
}

CongestionControlType BrutalSender::GetCongestionControlType() const {
  return kBrutal;
}

void BrutalSender::AdjustNetworkParameters(const NetworkParams& params) {
  fallback_.AdjustNetworkParameters(params);
}

std::string BrutalSender::GetDebugState() const {
  if (target_rate_bps_ == 0) {
    return fallback_.GetDebugState();
  }
  std::ostringstream out;
  out << "Brutal(target_bps=" << target_rate_bps_ << ", ack_rate=" << ack_rate_
      << ", effective_bps=" << CompensatedRateBps()
      << ", peer_max_ack_delay_us=" << peer_max_ack_delay_.ToMicroseconds()
      << ", cwnd=" << GetCongestionWindow() << ")";
  return out.str();
}

void BrutalSender::OnApplicationLimited(QuicByteCount bytes_in_flight) {
  fallback_.OnApplicationLimited(bytes_in_flight);
}

void BrutalSender::PopulateConnectionStats(QuicConnectionStats* stats) const {
  fallback_.PopulateConnectionStats(stats);
}

bool BrutalSender::EnableECT0() {
  return fallback_.EnableECT0();
}

bool BrutalSender::EnableECT1() {
  return fallback_.EnableECT1();
}

void BrutalSender::ReduceMemoryUsage() {
  fallback_.ReduceMemoryUsage();
}

void BrutalSender::RecordPacketOutcomes(QuicTime event_time,
                                        uint64_t acked,
                                        uint64_t lost) {
  if (!origin_.IsInitialized() || event_time < origin_) {
    origin_ = event_time;
  }
  const uint64_t sec =
      static_cast<uint64_t>((event_time - origin_).ToSeconds());
  PacketSlot& slot = slots_.at(static_cast<size_t>(sec % kAckRateWindowSeconds));
  if (slot.active && slot.second == sec) {
    slot.acked += acked;
    slot.lost += lost;
  } else {
    slot = PacketSlot{sec, acked, lost, true};
  }
  UpdateAckRate(sec);
}

void BrutalSender::UpdateAckRate(uint64_t current_second) {
  uint64_t ack_sum = 0;
  uint64_t loss_sum = 0;
  for (const PacketSlot& slot : slots_) {
    if (slot.active && current_second >= slot.second &&
        (current_second - slot.second) < kAckRateWindowSeconds) {
      ack_sum += slot.acked;
      loss_sum += slot.lost;
    }
  }
  const uint64_t total = ack_sum + loss_sum;
  if (total < kMinAckRateSamples) {
    ack_rate_ = 1.0;
    return;
  }
  const double observed =
      static_cast<double>(ack_sum) / static_cast<double>(total);
  ack_rate_ = std::clamp(observed, kMinAckRate, 1.0);
}

QuicByteCount BrutalSender::CalculateCongestionWindow() const {
  const uint64_t rate_bps = CompensatedRateBps();
  const int64_t raw_srtt_us =
      rtt_stats_ ? rtt_stats_->SmoothedOrInitialRtt().ToMicroseconds() : 0;
  const uint64_t srtt_us = static_cast<uint64_t>(
      std::clamp<int64_t>(raw_srtt_us, kMinRttUs, kMaxRttUs));
  const int64_t default_ack_delay_us =
      QuicTime::Delta::FromMilliseconds(kDefaultPeerDelayedAckTimeMs)
          .ToMicroseconds();
  const uint64_t ack_delay_us = static_cast<uint64_t>(std::clamp<int64_t>(
      peer_max_ack_delay_.ToMicroseconds(), default_ack_delay_us, kMaxRttUs));
  const uint64_t scaled_rtt_us = (srtt_us + ack_delay_us) * kCwndGain;
  const uint64_t whole = (rate_bps / kNumMicrosPerSecond) * scaled_rtt_us;
  const uint64_t rem =
      ((rate_bps % kNumMicrosPerSecond) * scaled_rtt_us) / kNumMicrosPerSecond;
  return std::max<QuicByteCount>(kMinCongestionWindowBytes, whole + rem);
}

}  // namespace quic
