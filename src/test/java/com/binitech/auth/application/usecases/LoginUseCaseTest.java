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
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class LoginUseCaseTest {
  private final Instant now = Instant.parse("2026-09-06T12:00:00Z");
  private final IdentityRepositoryPort identities = mock(IdentityRepositoryPort.class);
  private final RefreshSessionRepositoryPort sessions = mock(RefreshSessionRepositoryPort.class);
  private final SessionRevocationPort revocations = mock(SessionRevocationPort.class);
  private final AccessTokenPort tokens = mock(AccessTokenPort.class);
  private final PasswordHashPort passwords = mock(PasswordHashPort.class);
  private final LoginUseCase useCase =
      new LoginUseCase(
          identities,
          sessions,
          tokens,
          passwords,
          60000,
          revocations,
          Clock.fixed(now, ZoneOffset.UTC));
  private final Identity user = new Identity("user1", "admin", "hash", "OPERATOR", "tenant1", true);

  @Test
  void loginUsesPortsAndInjectedClock() {
    when(identities.findCandidates("admin", "tenant1")).thenReturn(List.of(user));
    when(passwords.matches("password", "hash")).thenReturn(true);
    when(revocations.sessionVersion("user1")).thenReturn(7L);
    when(tokens.issue(user, 7L)).thenReturn("access");
    var result = useCase.login("admin", "password", "tenant1");
    var saved = ArgumentCaptor.forClass(RefreshSession.class);
    verify(sessions).save(saved.capture());
    assertEquals(now.plusSeconds(60), saved.getValue().expiryDate());
    assertEquals(7L, saved.getValue().sessionVersion());
    assertEquals("access", result.accessToken());
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
