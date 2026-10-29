package com.binitech.auth.application.usecases;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.binitech.auth.application.ports.outbound.*;
import com.binitech.auth.domain.*;
import com.binitech.auth.domain.exception.InvalidCredentialsException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class LoginUseCaseTest {
  private final Instant now = Instant.parse("2026-09-06T12:00:00Z");
  private final IdentityRepositoryPort identities = mock(IdentityRepositoryPort.class);
  private final RefreshSessionRepositoryPort sessions = mock(RefreshSessionRepositoryPort.class);
  private final SessionRevocationPort revocations = mock(SessionRevocationPort.class);
  private final AccessTokenPort tokens = mock(AccessTokenPort.class);
  private final PasswordHashPort passwords = mock(PasswordHashPort.class);
  private final TwoFactorRepositoryPort twoFactor = mock(TwoFactorRepositoryPort.class);
  private final TwoFactorChallengeRepositoryPort challenges =
      mock(TwoFactorChallengeRepositoryPort.class);
  private final TotpPort totp = mock(TotpPort.class);
  private final LoginUseCase useCase =
      new LoginUseCase(
          identities,
          sessions,
          tokens,
          passwords,
          60000,
          revocations,
          twoFactor,
          challenges,
          totp,
          Clock.fixed(now, ZoneOffset.UTC));
  private final Identity user = new Identity("user1", "admin", "hash", "OPERATOR", "tenant1", true);

  @Test
  void loginUsesPortsAndInjectedClock() {
    when(identities.findCandidates("admin", "tenant1")).thenReturn(List.of(user));
    when(passwords.matches("password", "hash")).thenReturn(true);
    when(revocations.sessionVersion("user1")).thenReturn(7L);
    when(tokens.issue(user, 7L)).thenReturn("access");
    var result = (AuthResult) useCase.login("admin", "password", "tenant1");
    var saved = ArgumentCaptor.forClass(RefreshSession.class);
    verify(sessions).save(saved.capture());
    assertEquals(now.plusSeconds(60), saved.getValue().expiryDate());
    assertEquals(7L, saved.getValue().sessionVersion());
    assertEquals("access", result.accessToken());
  }

  @Test
  void loginWithTwoFactorEnabledReturnsChallengeWithoutIssuingTokens() {
    when(identities.findCandidates("admin", "tenant1")).thenReturn(List.of(user));
    when(passwords.matches("password", "hash")).thenReturn(true);
    when(revocations.sessionVersion("user1")).thenReturn(3L);
    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment("secret", null, 10L)));

    var result = useCase.login("admin", "password", "tenant1");

    var challenge = assertInstanceOf(TwoFactorChallenge.class, result);
    assertEquals(now.plusSeconds(300), challenge.expiresAt());
    var saved = ArgumentCaptor.forClass(PendingTwoFactorLogin.class);
    verify(challenges).save(saved.capture());
    assertEquals(AccountLifecycleUseCase.digest(challenge.challengeToken()), saved.getValue().id());
    assertEquals(3L, saved.getValue().sessionVersion());
    verifyNoInteractions(tokens, sessions);
  }

  @Test
  void completeTwoFactorLoginIssuesSessionAndBurnsCounter() {
    String digest = AccountLifecycleUseCase.digest("challenge");
    when(challenges.attempt(digest, now, 5))
        .thenReturn(
            Optional.of(
                new PendingTwoFactorLogin(digest, "user1", "tenant1", 3L, now.plusSeconds(60))));
    when(identities.findById("user1")).thenReturn(Optional.of(user));
    when(revocations.sessionVersion("user1")).thenReturn(3L);
    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment("secret", null, 10L)));
    when(totp.verify("secret", "123456", now)).thenReturn(OptionalLong.of(11L));
    when(twoFactor.markUsed("user1", 11L)).thenReturn(true);
    when(challenges.consume(digest)).thenReturn(true);
    when(tokens.issue(user, 3L)).thenReturn("access");

    assertEquals("access", useCase.completeTwoFactorLogin("challenge", "123456").accessToken());
  }

  @Test
  void completeTwoFactorLoginRejectsWrongReplayedOrExhaustedCodes() {
    String digest = AccountLifecycleUseCase.digest("challenge");
    var pending = new PendingTwoFactorLogin(digest, "user1", "tenant1", 0L, now.plusSeconds(60));
    when(challenges.attempt(digest, now, 5)).thenReturn(Optional.of(pending));
    when(identities.findById("user1")).thenReturn(Optional.of(user));
    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment("secret", null, 10L)));
    when(totp.verify("secret", "000000", now)).thenReturn(OptionalLong.empty());
    when(totp.verify("secret", "123456", now)).thenReturn(OptionalLong.of(10L));

    assertThrows(
        InvalidCredentialsException.class,
        () -> useCase.completeTwoFactorLogin("challenge", "000000"));
    assertThrows(
        InvalidCredentialsException.class,
        () -> useCase.completeTwoFactorLogin("challenge", "123456"));
    when(challenges.attempt(digest, now, 5)).thenReturn(Optional.empty());
    assertThrows(
        InvalidCredentialsException.class,
        () -> useCase.completeTwoFactorLogin("challenge", "123456"));
    verify(challenges, never()).consume(anyString());
    verifyNoInteractions(tokens, sessions);
  }

  @Test
  void refreshAtExpirationIsRejectedWithoutIssuingTokens() {
    when(sessions.consume("expired"))
        .thenReturn(Optional.of(new RefreshSession(null, "expired", "user1", "tenant1", now, 0L)));
    assertThrows(InvalidCredentialsException.class, () -> useCase.refresh("expired"));
    verifyNoInteractions(tokens, identities);
  }

  @Test
  void logoutUsesTokenRemainingLifetime() {
    when(tokens.parse("access"))
        .thenReturn(new AccessTokenClaims("user1", 0L, now.plusSeconds(15)));
    when(identities.findById("user1")).thenReturn(Optional.of(user));
    useCase.logout("access");
    verify(revocations).blacklist("access", 15000);
    verify(sessions).deleteForUser("user1", "tenant1");
  }
}
