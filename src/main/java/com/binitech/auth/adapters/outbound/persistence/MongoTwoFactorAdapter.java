package com.binitech.auth.adapters.outbound.persistence;

import com.binitech.auth.application.ports.outbound.TwoFactorRepositoryPort;
import com.binitech.auth.domain.TwoFactorEnrollment;
import com.binitech.auth.domain.TwoFactorFailure;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.ReturnDocument;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class MongoTwoFactorAdapter implements TwoFactorRepositoryPort {
  private static final String SECRET = "totpSecret";
  private static final String PENDING_SECRET = "totpPendingSecret";
  private static final String LAST_COUNTER = "totpLastCounter";
  private static final String ENABLED_AT = "totpEnabledAt";
  private static final String FAILED_ATTEMPTS = "totpFailedAttempts";
  private static final String LOCKED_UNTIL = "totpLockedUntil";
  private static final String RECOVERY_CODES = "totpRecoveryCodes";
  private static final String SET = "$set";
  private static final String EXISTS = "$exists";

  private final MongoCollection<Document> identities;
  private final String application;

  public MongoTwoFactorAdapter(
      MongoTemplate mongo, @Value("${auth.application-id:pdv}") String application) {
    this.identities = mongo.getCollection("identities");
    this.application = application;
  }

  private Document identity(String userId) {
    return new Document("applicationId", application).append("_id", userId);
  }

  public Optional<TwoFactorEnrollment> find(String userId) {
    return Optional.ofNullable(identities.find(identity(userId)).first())
        .map(
            d ->
                new TwoFactorEnrollment(
                    d.getString(SECRET),
                    d.getString(PENDING_SECRET),
                    ((Number) d.getOrDefault(LAST_COUNTER, -1L)).longValue(),
                    Optional.ofNullable(d.getDate(LOCKED_UNTIL)).map(Date::toInstant).orElse(null),
                    d.getList(RECOVERY_CODES, String.class, List.of())));
  }

  public boolean savePending(String userId, String secret) {
    return identities
            .updateOne(
                identity(userId).append(SECRET, new Document(EXISTS, false)),
                new Document(SET, new Document(PENDING_SECRET, secret)))
            .getMatchedCount()
        == 1;
  }

  public boolean activate(
      String userId, String pendingSecret, long counter, List<String> recoveryCodes) {
    return identities
            .updateOne(
                identity(userId)
                    .append(PENDING_SECRET, pendingSecret)
                    .append(SECRET, new Document(EXISTS, false)),
                new Document(
                        SET,
                        new Document(SECRET, pendingSecret)
                            .append(LAST_COUNTER, counter)
                            .append(RECOVERY_CODES, recoveryCodes)
                            .append(ENABLED_AT, Date.from(Instant.now())))
                    .append("$unset", new Document(PENDING_SECRET, "")))
            .getModifiedCount()
        == 1;
  }

  public boolean markUsed(String userId, long counter) {
    return identities
            .updateOne(
                identity(userId)
                    .append(SECRET, new Document(EXISTS, true))
                    .append(LAST_COUNTER, new Document("$lt", counter)),
                new Document(SET, new Document(LAST_COUNTER, counter).append(FAILED_ATTEMPTS, 0)))
            .getModifiedCount()
        == 1;
  }

  public boolean useRecoveryCode(String userId, String secret, String recoveryCode) {
    return identities
            .updateOne(
                identity(userId).append(SECRET, secret).append(RECOVERY_CODES, recoveryCode),
                new Document("$pull", new Document(RECOVERY_CODES, recoveryCode))
                    .append(SET, new Document(FAILED_ATTEMPTS, 0)))
            .getModifiedCount()
        == 1;
  }

  public boolean replaceRecoveryCodes(String userId, String secret, List<String> recoveryCodes) {
    return identities
            .updateOne(
                identity(userId).append(SECRET, secret),
                new Document(SET, new Document(RECOVERY_CODES, recoveryCodes)))
            .getMatchedCount()
        == 1;
  }

  public boolean disable(String userId, String secret) {
    return identities
            .updateOne(identity(userId).append(SECRET, secret), clearTwoFactor())
            .getModifiedCount()
        == 1;
  }

  public boolean reset(String userId) {
    return identities
            .updateOne(
                identity(userId)
                    .append(
                        "$or",
                        List.of(
                            new Document(SECRET, new Document(EXISTS, true)),
                            new Document(PENDING_SECRET, new Document(EXISTS, true)))),
                clearTwoFactor())
            .getModifiedCount()
        == 1;
  }

  private static Document clearTwoFactor() {
    return new Document(
        "$unset",
        new Document(SECRET, "")
            .append(PENDING_SECRET, "")
            .append(LAST_COUNTER, "")
            .append(ENABLED_AT, "")
            .append(FAILED_ATTEMPTS, "")
            .append(LOCKED_UNTIL, "")
            .append(RECOVERY_CODES, ""));
  }

  public TwoFactorFailure registerFailure(String userId, int maxFailures, Instant lockUntil) {
    Document reachedLimit = new Document("$gte", List.of("$" + FAILED_ATTEMPTS, maxFailures));
    Document after =
        identities.findOneAndUpdate(
            identity(userId).append(SECRET, new Document(EXISTS, true)),
            List.of(
                new Document(
                    SET,
                    new Document(
                        FAILED_ATTEMPTS,
                        new Document(
                            "$add",
                            List.of(
                                new Document("$ifNull", List.of("$" + FAILED_ATTEMPTS, 0)), 1)))),
                new Document(
                    SET,
                    new Document(
                            LOCKED_UNTIL,
                            new Document(
                                "$cond",
                                List.of(reachedLimit, Date.from(lockUntil), "$" + LOCKED_UNTIL)))
                        .append(
                            FAILED_ATTEMPTS,
                            new Document(
                                "$cond", List.of(reachedLimit, 0, "$" + FAILED_ATTEMPTS))))),
            new FindOneAndUpdateOptions().returnDocument(ReturnDocument.AFTER));
    if (after == null) {
      return new TwoFactorFailure(maxFailures, null);
    }
    int failures = ((Number) after.getOrDefault(FAILED_ATTEMPTS, 0)).intValue();
    if (failures == 0) {
      return new TwoFactorFailure(0, after.getDate(LOCKED_UNTIL).toInstant());
    }
    return new TwoFactorFailure(maxFailures - failures, null);
  }
}
