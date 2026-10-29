package com.binitech.auth.application.usecases;

import com.binitech.auth.application.ports.outbound.TwoFactorRepositoryPort;
import com.binitech.auth.domain.TwoFactorEnrollment;
import com.binitech.auth.domain.TwoFactorFailure;
import com.binitech.auth.domain.exception.InvalidTwoFactorCodeException;
import com.binitech.auth.domain.exception.TwoFactorLockedException;
import java.time.Duration;
import java.time.Instant;

final class TwoFactorLockout {
  static final int MAX_FAILURES = 3;
  static final Duration LOCK_DURATION = Duration.ofHours(1);

  private TwoFactorLockout() {}

  static void ensureUnlocked(TwoFactorEnrollment enrollment, Instant now) {
    if (enrollment.lockedAt(now)) {
      throw new TwoFactorLockedException(enrollment.lockedUntil());
    }
  }

  static RuntimeException failure(TwoFactorRepositoryPort twoFactor, String userId, Instant now) {
    TwoFactorFailure failure =
        twoFactor.registerFailure(userId, MAX_FAILURES, now.plus(LOCK_DURATION));
    if (failure.locked()) {
      return new TwoFactorLockedException(failure.lockedUntil());
    }
    return new InvalidTwoFactorCodeException(failure.remainingAttempts());
  }
}
