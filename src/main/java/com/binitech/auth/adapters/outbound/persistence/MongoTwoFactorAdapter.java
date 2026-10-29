package com.binitech.auth.adapters.outbound.persistence;

import com.binitech.auth.application.ports.outbound.TwoFactorRepositoryPort;
import com.binitech.auth.domain.TwoFactorEnrollment;
import com.mongodb.client.MongoCollection;
import java.time.Instant;
import java.util.Date;
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
                    ((Number) d.getOrDefault("totpLastCounter", -1L)).longValue()));
  }

  public boolean savePending(String userId, String secret) {
    return identities
            .updateOne(
                identity(userId).append("totpSecret", new Document("$exists", false)),
                new Document("$set", new Document("totpPendingSecret", secret)))
            .getMatchedCount()
        == 1;
  }

  public boolean activate(String userId, String pendingSecret, long counter) {
    return identities
            .updateOne(
                identity(userId)
                    .append("totpPendingSecret", pendingSecret)
                    .append("totpSecret", new Document("$exists", false)),
                new Document(
                        "$set",
                        new Document("totpSecret", pendingSecret)
                            .append("totpLastCounter", counter)
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
                new Document("$set", new Document("totpLastCounter", counter)))
            .getModifiedCount()
        == 1;
  }

  public boolean disable(String userId, String secret, long counter) {
    return identities
            .updateOne(
                identity(userId)
                    .append("totpSecret", secret)
                    .append("totpLastCounter", new Document("$lt", counter)),
                new Document(
                    "$unset",
                    new Document("totpSecret", "")
                        .append("totpPendingSecret", "")
                        .append("totpLastCounter", "")
                        .append("totpEnabledAt", "")))
            .getModifiedCount()
        == 1;
  }
}
