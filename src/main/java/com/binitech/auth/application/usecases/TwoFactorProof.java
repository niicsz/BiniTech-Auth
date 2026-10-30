package com.binitech.auth.application.usecases;

import com.binitech.auth.application.ports.outbound.RecoveryCodePort;
import com.binitech.auth.application.ports.outbound.TotpPort;
import com.binitech.auth.application.ports.outbound.TwoFactorRepositoryPort;
import com.binitech.auth.domain.TwoFactorEnrollment;
import java.time.Instant;

final class TwoFactorProof {
  private TwoFactorProof() {}

  static boolean accept(
      TwoFactorRepositoryPort twoFactor,
      TotpPort totp,
      RecoveryCodePort recoveryCodes,
      String userId,
      TwoFactorEnrollment enrollment,
      String code,
      Instant now) {
    var recovery = recoveryCodes.digest(code);
    if (recovery.isPresent()) {
      return twoFactor.useRecoveryCode(userId, enrollment.secret(), recovery.get());
    }
    var counter = totp.verify(enrollment.secret(), code, now);
    return counter.isPresent() && twoFactor.markUsed(userId, counter.getAsLong());
  }
}
