package com.binitech.auth.adapters.outbound.persistence;

import static org.junit.jupiter.api.Assertions.*;

import com.binitech.auth.domain.Account;
import com.binitech.auth.domain.PendingTwoFactorLogin;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import java.time.*;
import java.util.List;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.mongodb.core.MongoTemplate;

@EnabledIfEnvironmentVariable(named = "AUTH_TEST_MONGODB_URI", matches = ".+")
class MongoAdaptersIT {
  static MongoClient client;
  MongoTemplate mongo;
  MongoAccountAdapter accounts;
  MongoSessionRevocationAdapter revocations;

  @BeforeAll
  static void connect() {
    client = MongoClients.create(System.getenv("AUTH_TEST_MONGODB_URI"));
  }

  @AfterAll
  static void close() {
    client.getDatabase("binitech_auth_adapter_test").drop();
    client.close();
  }

  @BeforeEach
  void setup() {
    mongo = new MongoTemplate(client, "binitech_auth_adapter_test");
    mongo.getDb().drop();
    accounts = new MongoAccountAdapter(mongo, "pdv");
    revocations = new MongoSessionRevocationAdapter(mongo, Clock.systemUTC());
  }

  @Test
  void purgeTenantRemovesOnlyThatTenantIdentitiesAndSessions() {
    accounts.provision(new Account("a1", "ana", "hash", "t1", true, false, null));
    accounts.provision(new Account("a2", "bia", "hash", "t1", true, false, null));
    accounts.provision(new Account("b1", "ana", "hash", "t2", true, false, null));
    new MongoAccountAdapter(mongo, "another-app")
        .provision(new Account("x1", "ana", "hash", "t1", true, false, null));
    mongo
        .getCollection("refresh_tokens")
        .insertOne(new org.bson.Document("token", "r1").append("tenantId", "t1"));
    mongo
        .getCollection("refresh_tokens")
        .insertOne(new org.bson.Document("token", "r2").append("tenantId", "t2"));

    assertEquals(2, accounts.purgeTenant("t1"));

    assertTrue(accounts.find("a1").isEmpty());
    assertTrue(accounts.find("a2").isEmpty());
    assertTrue(accounts.find("b1").isPresent());
    assertTrue(new MongoAccountAdapter(mongo, "another-app").find("x1").isPresent());
    assertEquals(1, mongo.getCollection("refresh_tokens").countDocuments());
  }

  @Test
  void preservesObjectIdShapedStringIdentityAndInsertOnlyCredentials() {
    String id = "507f1f77bcf86cd799439011";
    Account original =
        new Account(id, "user", "hash", "tenant", true, false, "recovery@example.com");
    assertEquals(original, accounts.provision(original));
    assertEquals(original, accounts.find(id).orElseThrow());
    assertEquals(
        original,
        accounts.provision(new Account(id, "other", "replacement", "other", false, false, null)));
    assertEquals(id, new MongoIdentityAdapter(mongo).findById(id).orElseThrow().id());
    assertEquals(0, revocations.sessionVersion(id));
    revocations.revoke(id);
    assertEquals(1, revocations.sessionVersion(id));
    assertTrue(new MongoAccountAdapter(mongo, "another-app").find(id).isEmpty());
  }

  @Test
  void passwordUpdateAtomicallyRevokesSessionsAndInvalidatesRecovery() {
    accounts.provision(
        new Account("user", "user", "hash", null, true, false, "recovery@example.com"));
    accounts.requestRecovery("user", "hash", "digest", Instant.now().plusSeconds(60));
    assertTrue(accounts.changePassword("user", "hash", "replacement"));
    assertFalse(accounts.changePassword("user", "hash", "stale"));
    assertEquals(1, revocations.sessionVersion("user"));
    assertFalse(accounts.completeRecovery("digest", "stale", Instant.now()));
  }

  @Test
  void recoveryIsSingleUseAndHonorsExpiration() {
    accounts.provision(
        new Account("user", "user", "hash", null, true, false, "recovery@example.com"));
    Instant now = Instant.now();
    accounts.requestRecovery("user", "hash", "expired", now);
    assertFalse(accounts.completeRecovery("expired", "invalid", now));
    accounts.requestRecovery("user", "hash", "valid", now.plusSeconds(60));
    assertTrue(accounts.completeRecovery("valid", "replacement", now));
    assertFalse(accounts.completeRecovery("valid", "replayed", now));
    assertEquals(1, revocations.sessionVersion("user"));
    assertEquals("replacement", accounts.find("user").orElseThrow().password());
  }

  @Test
  void twoFactorEnrollmentActivatesOnceAndRejectsReplayedCounters() {
    accounts.provision(new Account("user", "user", "hash", "t1", true, false, null));
    var twoFactor = new MongoTwoFactorAdapter(mongo, "pdv");
    assertFalse(new MongoTwoFactorAdapter(mongo, "another-app").savePending("user", "s"));
    assertTrue(twoFactor.savePending("user", "secret"));
    assertFalse(twoFactor.activate("user", "other", 10, List.of("r1")));
    assertTrue(twoFactor.activate("user", "secret", 10, List.of("r1", "r2")));
    assertFalse(twoFactor.savePending("user", "replacement"));
    var enrollment = twoFactor.find("user").orElseThrow();
    assertTrue(enrollment.enabled());
    assertEquals(10L, enrollment.lastCounter());
    assertEquals(List.of("r1", "r2"), enrollment.recoveryCodes());
    assertFalse(twoFactor.markUsed("user", 10));
    assertTrue(twoFactor.markUsed("user", 11));
    assertFalse(twoFactor.disable("user", "other"));
    assertTrue(twoFactor.disable("user", "secret"));
    var disabled = twoFactor.find("user").orElseThrow();
    assertFalse(disabled.enabled());
    assertTrue(disabled.recoveryCodes().isEmpty());
  }

  @Test
  void recoveryCodesAreSingleUseReplaceableAndResetClearsEverything() {
    accounts.provision(new Account("user", "user", "hash", "t1", true, false, null));
    var twoFactor = new MongoTwoFactorAdapter(mongo, "pdv");
    twoFactor.savePending("user", "secret");
    twoFactor.activate("user", "secret", 10, List.of("r1", "r2"));
    Instant lockUntil = Instant.parse("2030-01-01T00:00:00Z");
    twoFactor.registerFailure("user", 3, lockUntil);

    assertFalse(twoFactor.useRecoveryCode("user", "other", "r1"));
    assertTrue(twoFactor.useRecoveryCode("user", "secret", "r1"));
    assertFalse(twoFactor.useRecoveryCode("user", "secret", "r1"));
    assertEquals(List.of("r2"), twoFactor.find("user").orElseThrow().recoveryCodes());
    assertEquals(2, twoFactor.registerFailure("user", 3, lockUntil).remainingAttempts());
    assertTrue(twoFactor.replaceRecoveryCodes("user", "secret", List.of("r3")));
    assertFalse(twoFactor.useRecoveryCode("user", "secret", "r2"));
    assertTrue(twoFactor.useRecoveryCode("user", "secret", "r3"));

    assertTrue(twoFactor.reset("user"));
    assertFalse(twoFactor.reset("user"));
    assertFalse(twoFactor.reset("missing"));
    var cleared = twoFactor.find("user").orElseThrow();
    assertFalse(cleared.enabled());
    assertNull(cleared.lockedUntil());
    assertTrue(twoFactor.savePending("user", "fresh"));
  }

  @Test
  void threeTwoFactorFailuresLockUntilGivenInstantAndSuccessResetsCount() {
    accounts.provision(new Account("user", "user", "hash", "t1", true, false, null));
    var twoFactor = new MongoTwoFactorAdapter(mongo, "pdv");
    twoFactor.savePending("user", "secret");
    twoFactor.activate("user", "secret", 10, List.of());
    Instant lockUntil = Instant.parse("2030-01-01T00:00:00Z");

    assertEquals(2, twoFactor.registerFailure("user", 3, lockUntil).remainingAttempts());
    assertTrue(twoFactor.markUsed("user", 11));
    assertEquals(2, twoFactor.registerFailure("user", 3, lockUntil).remainingAttempts());
    assertEquals(1, twoFactor.registerFailure("user", 3, lockUntil).remainingAttempts());
    var locked = twoFactor.registerFailure("user", 3, lockUntil);
    assertTrue(locked.locked());
    assertEquals(lockUntil, locked.lockedUntil());
    assertEquals(lockUntil, twoFactor.find("user").orElseThrow().lockedUntil());
    assertTrue(
        twoFactor.find("user").orElseThrow().lockedAt(Instant.parse("2029-12-31T23:00:00Z")));
    assertEquals(2, twoFactor.registerFailure("user", 3, lockUntil).remainingAttempts());
  }

  @Test
  void twoFactorChallengeLimitsAttemptsExpiresAndIsSingleUse() {
    var challenges = new MongoTwoFactorChallengeAdapter(mongo);
    Instant now = Instant.now();
    challenges.save(new PendingTwoFactorLogin("c1", "user", "t1", 2L, now.plusSeconds(60)));
    challenges.save(new PendingTwoFactorLogin("c2", "user", "t1", 0L, now));
    assertTrue(challenges.attempt("c2", now, 5).isEmpty());
    assertEquals(2L, challenges.attempt("c1", now, 2).orElseThrow().sessionVersion());
    assertTrue(challenges.attempt("c1", now, 2).isPresent());
    assertTrue(challenges.attempt("c1", now, 2).isEmpty());
    assertTrue(challenges.consume("c1"));
    assertFalse(challenges.consume("c1"));
  }
}
