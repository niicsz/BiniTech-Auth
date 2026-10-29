package com.binitech.auth.application.usecases;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.binitech.auth.application.ports.inbound.AuthenticationUseCase;
import com.binitech.auth.application.ports.outbound.*;
import com.binitech.auth.domain.*;
import com.binitech.auth.domain.exception.InvalidTwoFactorCodeException;
import com.binitech.auth.domain.exception.TwoFactorConflictException;
import com.binitech.auth.domain.exception.TwoFactorLockedException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.OptionalLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TwoFactorUseCaseTest {
  private final Instant now = Instant.parse("2026-10-29T12:00:00Z");
  private final AuthenticationUseCase authentication = mock(AuthenticationUseCase.class);
  private final TwoFactorRepositoryPort twoFactor = mock(TwoFactorRepositoryPort.class);
  private final TotpPort totp = mock(TotpPort.class);
  private final TwoFactorUseCase useCase =
      new TwoFactorUseCase(authentication, twoFactor, totp, Clock.fixed(now, ZoneOffset.UTC));

  @BeforeEach
  void setUp() {
    when(authentication.session("access"))
        .thenReturn(new SessionIdentity("user1", "ana", null, "tenant1"));
  }

  @Test
  void setupStoresPendingSecretAndReturnsProvisioning() {
    var setup = new TwoFactorSetup("c2VjcmV0", "otpauth://totp/x", "SHA512", 6, 30);
    when(totp.provision("ana")).thenReturn(setup);
    when(twoFactor.savePending("user1", "c2VjcmV0")).thenReturn(true);

    assertEquals(setup, useCase.setup("access"));
  }

  @Test
  void setupIsRejectedWhenAlreadyEnabled() {
    when(totp.provision("ana"))
        .thenReturn(new TwoFactorSetup("c2VjcmV0", "otpauth://totp/x", "SHA512", 6, 30));

    assertThrows(TwoFactorConflictException.class, () -> useCase.setup("access"));
  }

  @Test
  void enableActivatesPendingSecretWithVerifiedCounter() {
    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment(null, "pending", -1L, null)));
    when(totp.verify("pending", "123456", now)).thenReturn(OptionalLong.of(42L));
    when(twoFactor.activate("user1", "pending", 42L)).thenReturn(true);

    useCase.enable("access", "123456");

    verify(twoFactor).activate("user1", "pending", 42L);
  }

  @Test
  void enableRejectsWrongCodeAndMissingSetup() {
    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment(null, "pending", -1L, null)));
    when(totp.verify("pending", "000000", now)).thenReturn(OptionalLong.empty());
    assertThrows(InvalidTwoFactorCodeException.class, () -> useCase.enable("access", "000000"));

    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment(null, null, -1L, null)));
    assertThrows(TwoFactorConflictException.class, () -> useCase.enable("access", "000000"));
    verify(twoFactor, never()).activate(anyString(), anyString(), anyLong());
  }

  @Test
  void disableIsBlockedWhileLockedAndThirdFailureLocks() {
    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment("active", null, 42L, now.plusSeconds(60))));
    assertThrows(TwoFactorLockedException.class, () -> useCase.disable("access", "123456"));
    verifyNoInteractions(totp);

    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment("active", null, 42L, null)));
    when(totp.verify("active", "000000", now)).thenReturn(OptionalLong.empty());
    when(twoFactor.registerFailure("user1", 3, now.plusSeconds(3600)))
        .thenReturn(new TwoFactorFailure(0, now.plusSeconds(3600)));
    var locked =
        assertThrows(TwoFactorLockedException.class, () -> useCase.disable("access", "000000"));
    assertEquals(now.plusSeconds(3600), locked.lockedUntil());
  }

  @Test
  void disableRequiresFreshCodeForActiveSecret() {
    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment("active", null, 42L, null)));
    when(totp.verify("active", "123456", now)).thenReturn(OptionalLong.of(42L));
    when(twoFactor.disable("user1", "active", 42L)).thenReturn(false);
    when(twoFactor.registerFailure("user1", 3, now.plusSeconds(3600)))
        .thenReturn(new TwoFactorFailure(1, null));

    var wrong =
        assertThrows(
            InvalidTwoFactorCodeException.class, () -> useCase.disable("access", "123456"));
    assertEquals(1, wrong.remainingAttempts());

    when(totp.verify("active", "654321", now)).thenReturn(OptionalLong.of(43L));
    when(twoFactor.disable("user1", "active", 43L)).thenReturn(true);
    useCase.disable("access", "654321");
    verify(twoFactor).disable("user1", "active", 43L);
  }
}
