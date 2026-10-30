package com.binitech.auth.application.usecases;

import com.binitech.auth.application.ports.inbound.AuthenticationUseCase;
import com.binitech.auth.application.ports.outbound.*;
import com.binitech.auth.domain.*;
import com.binitech.auth.domain.exception.InvalidCredentialsException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public class LoginUseCase implements AuthenticationUseCase {
  private static final Duration TWO_FACTOR_CHALLENGE_TTL = Duration.ofMinutes(5);
  private static final int TWO_FACTOR_MAX_ATTEMPTS = 5;
  private final IdentityRepositoryPort identities;
  private final RefreshSessionRepositoryPort sessions;
  private final AccessTokenPort tokens;
  private final PasswordHashPort passwords;
  private final long refreshExpiration;
  private final Clock clock;
  private final SessionRevocationPort revocations;
  private final TwoFactorRepositoryPort twoFactor;
  private final TwoFactorChallengeRepositoryPort challenges;
  private final TotpPort totp;
  private final RecoveryCodePort recoveryCodes;
  private final String dummyHash;

  public LoginUseCase(
      IdentityRepositoryPort identities,
      RefreshSessionRepositoryPort sessions,
      AccessTokenPort tokens,
      PasswordHashPort passwords,
      long refreshExpiration,
      SessionRevocationPort revocations,
      TwoFactorRepositoryPort twoFactor,
      TwoFactorChallengeRepositoryPort challenges,
      TotpPort totp,
      RecoveryCodePort recoveryCodes,
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
    this.twoFactor = twoFactor;
    this.challenges = challenges;
    this.totp = totp;
    this.recoveryCodes = recoveryCodes;
    this.dummyHash = passwords.encode(UUID.randomUUID().toString());
  }

  public LoginOutcome login(String username, String password, String tenantId) {
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
    long version = revocations.sessionVersion(match.id());
    var enrollment = twoFactor.find(match.id()).filter(TwoFactorEnrollment::enabled);
    if (enrollment.isPresent()) {
      TwoFactorLockout.ensureUnlocked(enrollment.get(), clock.instant());
      return challenge(match, version);
    }
    return issueSession(match, version);
  }

  public AuthResult completeTwoFactorLogin(String challengeToken, String code) {
    Instant now = clock.instant();
    PendingTwoFactorLogin pending =
        challenges
            .attempt(AccountLifecycleUseCase.digest(challengeToken), now, TWO_FACTOR_MAX_ATTEMPTS)
            .orElseThrow(InvalidCredentialsException::new);
    Identity identity =
        identities.findById(pending.userId()).orElseThrow(InvalidCredentialsException::new);
    long version = revocations.sessionVersion(identity.id());
    if (!identity.isActive()
        || !Objects.equals(identity.tenantId(), pending.tenantId())
        || version != pending.sessionVersion()) {
      throw new InvalidCredentialsException();
    }
    TwoFactorEnrollment enrollment =
        twoFactor
            .find(identity.id())
            .filter(TwoFactorEnrollment::enabled)
            .orElseThrow(InvalidCredentialsException::new);
    TwoFactorLockout.ensureUnlocked(enrollment, now);
    if (!TwoFactorProof.accept(
        twoFactor, totp, recoveryCodes, identity.id(), enrollment, code, now)) {
      throw TwoFactorLockout.failure(twoFactor, identity.id(), now);
    }
    if (!challenges.consume(pending.id())) {
      throw new InvalidCredentialsException();
    }
    return issueSession(identity, version);
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

  private TwoFactorChallenge challenge(Identity identity, long version) {
    String token = UUID.randomUUID() + "-" + UUID.randomUUID();
    Instant expiresAt = clock.instant().plus(TWO_FACTOR_CHALLENGE_TTL);
    challenges.save(
        new PendingTwoFactorLogin(
            AccountLifecycleUseCase.digest(token),
            identity.id(),
            identity.tenantId(),
            version,
            expiresAt));
    return new TwoFactorChallenge(token, expiresAt);
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
