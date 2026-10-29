package com.binitech.auth.domain;

import java.time.Instant;

public record TwoFactorEnrollment(
    String secret, String pendingSecret, long lastCounter, Instant lockedUntil) {
  public boolean enabled() {
    return secret != null && !secret.isBlank();
  }

  public boolean lockedAt(Instant now) {
    return lockedUntil != null && lockedUntil.isAfter(now);
  }
}
