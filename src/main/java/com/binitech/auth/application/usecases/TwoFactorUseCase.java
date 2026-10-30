package com.binitech.auth.application.usecases;

import com.binitech.auth.application.ports.inbound.AuthenticationUseCase;
import com.binitech.auth.application.ports.inbound.TwoFactorManagement;
import com.binitech.auth.application.ports.outbound.RecoveryCodePort;
import com.binitech.auth.application.ports.outbound.TotpPort;
import com.binitech.auth.application.ports.outbound.TwoFactorRepositoryPort;
import com.binitech.auth.domain.SessionIdentity;
import com.binitech.auth.domain.TwoFactorEnrollment;
import com.binitech.auth.domain.TwoFactorSetup;
import com.binitech.auth.domain.TwoFactorStatus;
import com.binitech.auth.domain.exception.InvalidCredentialsException;
import com.binitech.auth.domain.exception.InvalidTwoFactorCodeException;
import com.binitech.auth.domain.exception.TwoFactorConflictException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public class TwoFactorUseCase implements TwoFactorManagement {
  private final AuthenticationUseCase authentication;
  private final TwoFactorRepositoryPort twoFactor;
  private final TotpPort totp;
  private final RecoveryCodePort recoveryCodes;
  private final Clock clock;

  public TwoFactorUseCase(
      AuthenticationUseCase authentication,
      TwoFactorRepositoryPort twoFactor,
      TotpPort totp,
      RecoveryCodePort recoveryCodes,
      Clock clock) {
    this.authentication = authentication;
    this.twoFactor = twoFactor;
    this.totp = totp;
    this.recoveryCodes = recoveryCodes;
    this.clock = clock;
  }

  public TwoFactorStatus status(String accessToken) {
    SessionIdentity identity = authentication.session(accessToken);
    Instant now = clock.instant();
    return twoFactor
        .find(identity.userId())
        .filter(TwoFactorEnrollment::enabled)
        .map(
            e ->
                new TwoFactorStatus(
                    true, e.lockedAt(now) ? e.lockedUntil() : null, e.recoveryCodes().size()))
        .orElse(new TwoFactorStatus(false, null, 0));
  }

  public TwoFactorSetup setup(String accessToken) {
    SessionIdentity identity = authentication.session(accessToken);
    TwoFactorSetup setup = totp.provision(identity.username());
    if (!twoFactor.savePending(identity.userId(), setup.secret())) {
      throw new TwoFactorConflictException();
    }
    return setup;
  }

  public List<String> enable(String accessToken, String code) {
    SessionIdentity identity = authentication.session(accessToken);
    TwoFactorEnrollment enrollment =
        twoFactor
            .find(identity.userId())
            .filter(e -> !e.enabled() && e.pendingSecret() != null)
            .orElseThrow(TwoFactorConflictException::new);
    long counter =
        totp.verify(enrollment.pendingSecret(), code, clock.instant())
            .orElseThrow(InvalidTwoFactorCodeException::new);
    List<String> codes = recoveryCodes.generate();
    if (!twoFactor.activate(
        identity.userId(), enrollment.pendingSecret(), counter, digests(codes))) {
      throw new TwoFactorConflictException();
    }
    return codes;
  }

  public List<String> regenerateRecoveryCodes(String accessToken, String code) {
    SessionIdentity identity = authentication.session(accessToken);
    TwoFactorEnrollment enrollment = verified(identity, code);
    List<String> codes = recoveryCodes.generate();
    if (!twoFactor.replaceRecoveryCodes(identity.userId(), enrollment.secret(), digests(codes))) {
      throw new TwoFactorConflictException();
    }
    return codes;
  }

  public void disable(String accessToken, String code) {
    SessionIdentity identity = authentication.session(accessToken);
    TwoFactorEnrollment enrollment = verified(identity, code);
    if (!twoFactor.disable(identity.userId(), enrollment.secret())) {
      throw new TwoFactorConflictException();
    }
  }

  public boolean reset(String identityId) {
    if (identityId == null || identityId.isBlank()) {
      throw new InvalidCredentialsException();
    }
    return twoFactor.reset(identityId);
  }

  private TwoFactorEnrollment verified(SessionIdentity identity, String code) {
    TwoFactorEnrollment enrollment =
        twoFactor
            .find(identity.userId())
            .filter(TwoFactorEnrollment::enabled)
            .orElseThrow(TwoFactorConflictException::new);
    Instant now = clock.instant();
    TwoFactorLockout.ensureUnlocked(enrollment, now);
    if (!TwoFactorProof.accept(
        twoFactor, totp, recoveryCodes, identity.userId(), enrollment, code, now)) {
      throw TwoFactorLockout.failure(twoFactor, identity.userId(), now);
    }
    return enrollment;
  }

  private List<String> digests(List<String> codes) {
    return codes.stream().map(recoveryCodes::digest).map(Optional::orElseThrow).toList();
  }
}
