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
                    d.getString("totpSecret"),
                    d.getString("totpPendingSecret"),
                    ((Number) d.getOrDefault("totpLastCounter", -1L)).longValue(),
                    Optional.ofNullable(d.getDate("totpLockedUntil"))
                        .map(Date::toInstant)
                        .orElse(null),
                    d.getList("totpRecoveryCodes", String.class, List.of())));
  }

  public boolean savePending(String userId, String secret) {
    return identities
            .updateOne(
                identity(userId).append("totpSecret", new Document("$exists", false)),
                new Document("$set", new Document("totpPendingSecret", secret)))
            .getMatchedCount()
        == 1;
  }

  public boolean activate(
      String userId, String pendingSecret, long counter, List<String> recoveryCodes) {
    return identities
            .updateOne(
                identity(userId)
                    .append("totpPendingSecret", pendingSecret)
                    .append("totpSecret", new Document("$exists", false)),
                new Document(
                        "$set",
                        new Document("totpSecret", pendingSecret)
                            .append("totpLastCounter", counter)
                            .append("totpRecoveryCodes", recoveryCodes)
                            .append("totpEnabledAt", Date.from(Instant.now())))
                    .append("$unset", new Document("totpPendingSecret", "")))
            .getModifiedCount()
        == 1;
  }

  public boolean markUsed(String userId, long counter) {
    return identities
            .updateOne(
                identity(userId)
                    .append("totpSecret", new Document("$exists", true))
                    .append("totpLastCounter", new Document("$lt", counter)),
                new Document(
                    "$set",
                    new Document("totpLastCounter", counter).append("totpFailedAttempts", 0)))
            .getModifiedCount()
        == 1;
  }

  public boolean useRecoveryCode(String userId, String secret, String recoveryCode) {
    return identities
            .updateOne(
                identity(userId)
                    .append("totpSecret", secret)
                    .append("totpRecoveryCodes", recoveryCode),
                new Document("$pull", new Document("totpRecoveryCodes", recoveryCode))
                    .append("$set", new Document("totpFailedAttempts", 0)))
            .getModifiedCount()
        == 1;
  }

  public boolean replaceRecoveryCodes(String userId, String secret, List<String> recoveryCodes) {
    return identities
            .updateOne(
                identity(userId).append("totpSecret", secret),
                new Document("$set", new Document("totpRecoveryCodes", recoveryCodes)))
            .getMatchedCount()
        == 1;
  }

  public boolean disable(String userId, String secret) {
    return identities
            .updateOne(identity(userId).append("totpSecret", secret), clearTwoFactor())
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
                            new Document("totpSecret", new Document("$exists", true)),
                            new Document("totpPendingSecret", new Document("$exists", true)))),
                clearTwoFactor())
            .getModifiedCount()
        == 1;
  }

  private static Document clearTwoFactor() {
    return new Document(
        "$unset",
        new Document("totpSecret", "")
            .append("totpPendingSecret", "")
            .append("totpLastCounter", "")
            .append("totpEnabledAt", "")
            .append("totpFailedAttempts", "")
            .append("totpLockedUntil", "")
            .append("totpRecoveryCodes", ""));
  }

  public TwoFactorFailure registerFailure(String userId, int maxFailures, Instant lockUntil) {
    Document reachedLimit = new Document("$gte", List.of("$totpFailedAttempts", maxFailures));
    Document after =
        identities.findOneAndUpdate(
            identity(userId).append("totpSecret", new Document("$exists", true)),
            List.of(
                new Document(
                    "$set",
                    new Document(
                        "totpFailedAttempts",
                        new Document(
                            "$add",
                            List.of(
                                new Document("$ifNull", List.of("$totpFailedAttempts", 0)), 1)))),
                new Document(
                    "$set",
                    new Document(
                            "totpLockedUntil",
                            new Document(
                                "$cond",
                                List.of(reachedLimit, Date.from(lockUntil), "$totpLockedUntil")))
                        .append(
                            "totpFailedAttempts",
                            new Document(
                                "$cond", List.of(reachedLimit, 0, "$totpFailedAttempts"))))),
            new FindOneAndUpdateOptions().returnDocument(ReturnDocument.AFTER));
    if (after == null) {
      return new TwoFactorFailure(maxFailures, null);
    }
    int failures = ((Number) after.getOrDefault("totpFailedAttempts", 0)).intValue();
    if (failures == 0) {
      return new TwoFactorFailure(0, after.getDate("totpLockedUntil").toInstant());
    }
    return new TwoFactorFailure(maxFailures - failures, null);
  }
}
