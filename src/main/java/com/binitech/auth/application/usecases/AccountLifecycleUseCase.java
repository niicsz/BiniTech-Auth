package com.binitech.auth.application.usecases;

import com.binitech.auth.application.ports.inbound.AccountLifecycle;
import com.binitech.auth.application.ports.outbound.*;
import com.binitech.auth.domain.*;
import com.binitech.auth.domain.exception.InvalidCredentialsException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

public class AccountLifecycleUseCase implements AccountLifecycle {
  private final AccountRepositoryPort accounts;
  private final PasswordHashPort passwords;
  private final SessionRevocationPort revocations;
  private final Clock clock;

  public AccountLifecycleUseCase(
      AccountRepositoryPort accounts,
      PasswordHashPort passwords,
      SessionRevocationPort revocations,
      Clock clock) {
    this.accounts = accounts;
    this.passwords = passwords;
    this.revocations = revocations;
    this.clock = clock;
  }

  public void provision(
      String id, String username, String password, String tenantId, String recoveryEmail) {
    requirePassword(password);
    Account existing = accounts.find(id).orElse(null);
    if (existing != null) {
      if (!existing.username().equals(username)
          || !java.util.Objects.equals(existing.tenantId(), tenantId)
          || !passwords.matches(password, existing.password()))
        throw new InvalidCredentialsException();
      return;
    }
    Account created =
        accounts.provision(
            new Account(
                id, username, passwords.encode(password), tenantId, true, false, recoveryEmail));
    if (!created.id().equals(id) || !passwords.matches(password, created.password())) {
      throw new InvalidCredentialsException();
    }
  }

  public void changePassword(String id, String currentPassword, String newPassword) {
    requirePassword(newPassword);
    Account account = accounts.find(id).orElseThrow(InvalidCredentialsException::new);
    if (!account.active()
        || account.managedCredential()
        || !passwords.matches(currentPassword, account.password())
        || !accounts.changePassword(id, account.password(), passwords.encode(newPassword))) {
      throw new InvalidCredentialsException();
    }
  }

  public Optional<RecoveryDelivery> requestRecovery(String username) {
    var candidates =
        accounts.findByUsername(username.trim()).stream()
            .filter(
                a ->
                    a.active()
                        && !a.managedCredential()
                        && a.recoveryEmail() != null
                        && !a.recoveryEmail().isBlank())
            .toList();
    if (candidates.size() != 1) return Optional.empty();
    Account account = candidates.getFirst();
    String token = UUID.randomUUID() + "-" + UUID.randomUUID();
    accounts.requestRecovery(
        account.id(), account.password(), digest(token), clock.instant().plusSeconds(3600));
    return Optional.of(new RecoveryDelivery(account.username(), account.recoveryEmail(), token));
  }

  public void completeRecovery(String token, String newPassword) {
    requirePassword(newPassword);
    if (!accounts.completeRecovery(digest(token), passwords.encode(newPassword), clock.instant())) {
      throw new InvalidCredentialsException();
    }
  }

  public void revokeSessions(String id) {
    accounts.find(id).orElseThrow(InvalidCredentialsException::new);
    revocations.revoke(id);
  }

  private void requirePassword(String password) {
    if (password == null || password.length() < 6 || password.length() > 1024) {
      throw new IllegalArgumentException("Password must contain 6 to 1024 characters");
    }
  }

  public static String digest(String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
