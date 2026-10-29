package com.binitech.auth.adapters.outbound.persistence;

import com.binitech.auth.application.ports.outbound.TwoFactorChallengeRepositoryPort;
import com.binitech.auth.domain.PendingTwoFactorLogin;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.ReturnDocument;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import org.bson.Document;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class MongoTwoFactorChallengeAdapter implements TwoFactorChallengeRepositoryPort {
  private final MongoCollection<Document> challenges;

  public MongoTwoFactorChallengeAdapter(MongoTemplate mongo) {
    this.challenges = mongo.getCollection("two_factor_challenges");
  }

  public void save(PendingTwoFactorLogin challenge) {
    challenges.insertOne(
        new Document("_id", challenge.id())
            .append("userId", challenge.userId())
            .append("tenantId", challenge.tenantId())
            .append("sessionVersion", challenge.sessionVersion())
            .append("expiresAt", Date.from(challenge.expiresAt()))
            .append("attempts", 0));
  }

  public Optional<PendingTwoFactorLogin> attempt(String id, Instant now, int maxAttempts) {
    return Optional.ofNullable(
            challenges.findOneAndUpdate(
                new Document("_id", id)
                    .append("expiresAt", new Document("$gt", Date.from(now)))
                    .append("attempts", new Document("$lt", maxAttempts)),
                new Document("$inc", new Document("attempts", 1)),
                new FindOneAndUpdateOptions().returnDocument(ReturnDocument.AFTER)))
        .map(
            d ->
                new PendingTwoFactorLogin(
                    d.getString("_id"),
                    d.getString("userId"),
                    d.getString("tenantId"),
                    ((Number) d.getOrDefault("sessionVersion", 0L)).longValue(),
                    d.getDate("expiresAt").toInstant()));
  }

  public boolean consume(String id) {
    return challenges.deleteOne(new Document("_id", id)).getDeletedCount() == 1;
  }
}
