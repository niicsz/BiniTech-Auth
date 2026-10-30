package com.binitech.auth.domain;

import java.time.Instant;
import java.util.List;

public record TwoFactorEnrollment(
    String secret,
    String pendingSecret,
    long lastCounter,
    Instant lockedUntil,
    List<String> recoveryCodes) {
  public TwoFactorEnrollment {
    recoveryCodes = recoveryCodes == null ? List.of() : List.copyOf(recoveryCodes);
  }

  public boolean enabled() {
    return secret != null && !secret.isBlank();
  }

  public boolean lockedAt(Instant now) {
    return lockedUntil != null && lockedUntil.isAfter(now);
  }
}
