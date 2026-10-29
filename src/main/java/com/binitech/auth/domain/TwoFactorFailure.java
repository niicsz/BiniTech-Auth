package com.binitech.auth.domain;

import java.time.Instant;

public record TwoFactorFailure(int remainingAttempts, Instant lockedUntil) {
  public boolean locked() {
    return lockedUntil != null;
  }
}
