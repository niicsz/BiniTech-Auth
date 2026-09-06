package com.binitech.auth.application.usecases;

import com.binitech.auth.application.ports.inbound.AuthenticationUseCase;
import com.binitech.auth.application.ports.outbound.*;
import com.binitech.auth.domain.*;
import com.binitech.auth.domain.exception.InvalidCredentialsException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public class LoginUseCase implements AuthenticationUseCase {
  private final IdentityRepositoryPort identities;
  private final RefreshSessionRepositoryPort sessions;
  private final AccessTokenPort tokens;
  private final PasswordHashPort passwords;
  private final long refreshExpiration;
  private final Clock clock;
  private final SessionRevocationPort revocations;
  private final String dummyHash;

  public LoginUseCase(
      IdentityRepositoryPort identities,
      RefreshSessionRepositoryPort sessions,
      AccessTokenPort tokens,
      PasswordHashPort passwords,
      long refreshExpiration,
      SessionRevocationPort revocations,
      Clock clock) {
    if (refreshExpiration <= 0) {
      throw new IllegalArgumentException("JWT_REFRESH_EXPIRATION deve ser positivo.");
    }
    this.clock = clock;
    this.revocations = revocations;
    this.identities = identities;
    this.sessions = sessions;
    this.tokens = tokens;
    this.passwords = passwords;
    this.refreshExpiration = refreshExpiration;
    this.dummyHash = passwords.encode(UUID.randomUUID().toString());
  }

  public AuthResult login(String username, String password, String tenantId) {
    List<Identity> candidates = identities.findCandidates(username, tenantId);
    if (candidates.isEmpty()) {
      passwords.matches(password, dummyHash);
      throw new InvalidCredentialsException();
    }
    Identity match = null;
    int matches = 0;
    for (Identity candidate : candidates) {
      if (passwordMatches(password, candidate.password())) {
        match = candidate;
        matches++;
      }
    }
    if (matches != 1 || !match.isActive()) {
      throw new InvalidCredentialsException();
    }
    // Independent logins can coexist, allowing several applications to use the identity service.
    return issueSession(match, revocations.sessionVersion(match.id()));
  }

  public AuthResult refresh(String token) {
    RefreshSession previous = sessions.consume(token).orElseThrow(InvalidCredentialsException::new);
    if (previous.isExpired(clock.instant())) {
      throw new InvalidCredentialsException();
    }
    Identity identity =
        identities.findById(previous.userId()).orElseThrow(InvalidCredentialsException::new);
    long version = revocations.sessionVersion(identity.id());
    long previousVersion = previous.version();
    if (!identity.isActive()
        || !Objects.equals(identity.tenantId(), previous.tenantId())
        || version != previousVersion) {
      throw new InvalidCredentialsException();
    }
    return issueSession(identity, version);
  }

  public SessionIdentity session(String token) {
    AccessTokenClaims claims = tokens.parse(token);
    String id = claims.userId();
    if (revocations.isBlacklisted(token)
        || revocations.sessionVersion(id) != claims.sessionVersion()) {
      throw new InvalidCredentialsException();
    }
    Identity identity = identities.findById(id).orElseThrow(InvalidCredentialsException::new);
    if (!identity.isActive()) {
      throw new InvalidCredentialsException();
    }
    return new SessionIdentity(
        identity.id(), identity.username(), identity.role(), identity.tenantId());
  }

  public void logout(String token) {
    SessionIdentity identity = session(token);
    AccessTokenClaims claims = tokens.parse(token);
    revocations.blacklist(
        token, Math.max(1, Duration.between(clock.instant(), claims.expiresAt()).toMillis()));
    sessions.deleteForUser(identity.userId(), identity.tenantId());
  }

  private boolean passwordMatches(String password, String hash) {
    try {
      return passwords.matches(password, hash);
    } catch (IllegalArgumentException exception) {
      return false;
    }
  }

  private AuthResult issueSession(Identity identity, long version) {
    String accessToken = tokens.issue(identity, version);
    String refreshToken = UUID.randomUUID().toString();
    sessions.save(
        new RefreshSession(
            null,
            refreshToken,
            identity.id(),
            identity.tenantId(),
            clock.instant().plusMillis(refreshExpiration),
            version));
    return new AuthResult(
        accessToken, refreshToken, identity.username(), identity.role(), identity.tenantId());
  }
}
