package com.binitech.auth.application.usecases;

import com.binitech.auth.application.ports.inbound.AuthenticationUseCase;
import com.binitech.auth.application.ports.inbound.TwoFactorManagement;
import com.binitech.auth.application.ports.outbound.TotpPort;
import com.binitech.auth.application.ports.outbound.TwoFactorRepositoryPort;
import com.binitech.auth.domain.SessionIdentity;
import com.binitech.auth.domain.TwoFactorEnrollment;
import com.binitech.auth.domain.TwoFactorSetup;
import com.binitech.auth.domain.exception.InvalidTwoFactorCodeException;
import com.binitech.auth.domain.exception.TwoFactorConflictException;
import java.time.Clock;

public class TwoFactorUseCase implements TwoFactorManagement {
  private final AuthenticationUseCase authentication;
  private final TwoFactorRepositoryPort twoFactor;
  private final TotpPort totp;
  private final Clock clock;

  public TwoFactorUseCase(
      AuthenticationUseCase authentication,
      TwoFactorRepositoryPort twoFactor,
      TotpPort totp,
      Clock clock) {
    this.authentication = authentication;
    this.twoFactor = twoFactor;
    this.totp = totp;
    this.clock = clock;
  }

  public TwoFactorSetup setup(String accessToken) {
    SessionIdentity identity = authentication.session(accessToken);
    TwoFactorSetup setup = totp.provision(identity.username());
    if (!twoFactor.savePending(identity.userId(), setup.secret())) {
      throw new TwoFactorConflictException();
    }
    return setup;
  }

  public void enable(String accessToken, String code) {
    SessionIdentity identity = authentication.session(accessToken);
    TwoFactorEnrollment enrollment =
        twoFactor
            .find(identity.userId())
            .filter(e -> !e.enabled() && e.pendingSecret() != null)
            .orElseThrow(TwoFactorConflictException::new);
    long counter =
        totp.verify(enrollment.pendingSecret(), code, clock.instant())
            .orElseThrow(InvalidTwoFactorCodeException::new);
    if (!twoFactor.activate(identity.userId(), enrollment.pendingSecret(), counter)) {
      throw new TwoFactorConflictException();
    }
  }

  public void disable(String accessToken, String code) {
    SessionIdentity identity = authentication.session(accessToken);
    TwoFactorEnrollment enrollment =
        twoFactor
            .find(identity.userId())
            .filter(TwoFactorEnrollment::enabled)
            .orElseThrow(TwoFactorConflictException::new);
    long counter =
        totp.verify(enrollment.secret(), code, clock.instant())
            .orElseThrow(InvalidTwoFactorCodeException::new);
    if (!twoFactor.disable(identity.userId(), enrollment.secret(), counter)) {
      throw new InvalidTwoFactorCodeException();
    }
  }
}
