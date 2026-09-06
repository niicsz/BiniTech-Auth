package com.binitech.auth.adapters.outbound.persistence;

import static org.junit.jupiter.api.Assertions.*;

import com.binitech.auth.domain.Account;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import java.time.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.mongodb.core.MongoTemplate;

/** Explicit opt-in: only the fixed disposable test database is touched, never production data. */
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
}
