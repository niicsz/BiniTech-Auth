package com.binitech.auth.application.usecases;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.binitech.auth.application.ports.outbound.*;
import com.binitech.auth.domain.*;
import com.binitech.auth.domain.exception.InvalidCredentialsException;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class AccountLifecycleUseCaseTest {
  AccountRepositoryPort accounts = mock(AccountRepositoryPort.class);
  PasswordHashPort passwords = mock(PasswordHashPort.class);
  SessionRevocationPort revocations = mock(SessionRevocationPort.class);
  Clock clock = Clock.fixed(Instant.parse("2026-09-06T12:00:00Z"), ZoneOffset.UTC);
  AccountLifecycleUseCase useCase =
      new AccountLifecycleUseCase(accounts, passwords, revocations, clock);
  Account account =
      new Account("user1", "user", "hash", "tenant", true, false, "recovery@example.com");

  @Test
  void changesPasswordUsingAtomicCompareAndSwap() {
    when(accounts.find("user1")).thenReturn(Optional.of(account));
    when(passwords.matches("current", "hash")).thenReturn(true);
    when(passwords.encode("new-password")).thenReturn("replacement");
    when(accounts.changePassword("user1", "hash", "replacement")).thenReturn(true);
    useCase.changePassword("user1", "current", "new-password");
    verify(accounts).changePassword("user1", "hash", "replacement");
  }

  @Test
  void rejectsWrongCurrentPassword() {
    when(accounts.find("user1")).thenReturn(Optional.of(account));
    assertThrows(
        InvalidCredentialsException.class,
        () -> useCase.changePassword("user1", "wrong", "new-password"));
    verify(accounts, never()).changePassword(any(), any(), any());
  }

  @Test
  void rejectsConcurrentPasswordChange() {
    when(accounts.find("user1")).thenReturn(Optional.of(account));
    when(passwords.matches("current", "hash")).thenReturn(true);
    when(passwords.encode("new-password")).thenReturn("replacement");
    assertThrows(
        InvalidCredentialsException.class,
        () -> useCase.changePassword("user1", "current", "new-password"));
  }

  @Test
  void managedCredentialCannotBeReset() {
    when(accounts.findByUsername("root"))
        .thenReturn(
            List.of(new Account("root", "root", "hash", null, true, true, "admin@example.com")));
    assertTrue(useCase.requestRecovery("root").isEmpty());
    verify(accounts, never()).requestRecovery(any(), any(), any(), any());
  }

  @Test
  void ambiguousRecoveryDoesNotIssueToken() {
    when(accounts.findByUsername("user")).thenReturn(List.of(account, account));
    assertTrue(useCase.requestRecovery("user").isEmpty());
  }

  @Test
  void storesDigestNotRawRecoveryToken() {
    when(accounts.findByUsername("user")).thenReturn(List.of(account));
    RecoveryDelivery delivery = useCase.requestRecovery("user").orElseThrow();
    assertEquals(account.recoveryEmail(), delivery.email());
    verify(accounts)
        .requestRecovery(
            "user1",
            "hash",
            AccountLifecycleUseCase.digest(delivery.token()),
            clock.instant().plusSeconds(3600));
    assertNotEquals(delivery.token(), AccountLifecycleUseCase.digest(delivery.token()));
  }

  @Test
  void expiredOrAlreadyUsedRecoveryIsRejected() {
    when(passwords.encode("new-password")).thenReturn("replacement");
    assertThrows(
        InvalidCredentialsException.class, () -> useCase.completeRecovery("used", "new-password"));
  }

  @Test
  void provisionRetryDoesNotReplaceCredentials() {
    when(accounts.find("user1")).thenReturn(Optional.of(account));
    when(passwords.matches("password", "hash")).thenReturn(true);
    useCase.provision("user1", "user", "password", "tenant", "other@example.com");
    verify(accounts, never()).provision(any());
  }

  @Test
  void anotherTenantCannotReuseIdentityId() {
    when(accounts.find("user1")).thenReturn(Optional.of(account));
    assertThrows(
        InvalidCredentialsException.class,
        () -> useCase.provision("user1", "user", "password", "another", null));
  }

  @Test
  void revokesOnlyExistingApplicationIdentity() {
    when(accounts.find("user1")).thenReturn(Optional.of(account));
    useCase.revokeSessions("user1");
    verify(revocations).revoke("user1");
    assertThrows(InvalidCredentialsException.class, () -> useCase.revokeSessions("other"));
    verify(revocations, never()).revoke("other");
  }
}
