package com.binitech.auth.domain;

import java.time.Instant;

public record RefreshSession(
    String id,
    String token,
    String userId,
    String tenantId,
    Instant expiryDate,
    Long sessionVersion) {
  public boolean isExpired(Instant now) {
    return expiryDate == null || !expiryDate.isAfter(now);
  }

  public long version() {
    return sessionVersion == null ? 0L : sessionVersion;
  }
}
