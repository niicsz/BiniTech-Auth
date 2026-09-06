package com.binitech.auth.adapters.outbound.persistence;

import com.binitech.auth.application.ports.outbound.SessionRevocationPort;
import com.binitech.auth.application.usecases.AccountLifecycleUseCase;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.UpdateOptions;
import java.time.Clock;
import java.util.Date;
import org.bson.Document;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Component;

@Component
public class MongoSessionRevocationAdapter implements SessionRevocationPort {
  private final MongoCollection<Document> identities;
  private final MongoCollection<Document> revoked;
  private final Clock clock;

  public MongoSessionRevocationAdapter(MongoTemplate mongo, Clock clock) {
    this.identities = mongo.getCollection("identities");
    this.revoked = mongo.getCollection("revoked_tokens");
    this.clock = clock;
  }

  public long sessionVersion(String userId) {
    Document d = identities.find(new Document("_id", userId)).first();
    return d == null ? -1L : ((Number) d.getOrDefault("sessionVersion", 0L)).longValue();
  }

  public void revoke(String userId) {
    identities.updateOne(
        new Document("_id", userId), new Document("$inc", new Document("sessionVersion", 1L)));
  }

  public boolean isBlacklisted(String token) {
    return revoked
            .find(
                new Document("_id", AccountLifecycleUseCase.digest(token))
                    .append("expiresAt", new Document("$gt", Date.from(clock.instant()))))
            .first()
        != null;
  }

  public void blacklist(String token, long ttlMillis) {
    revoked.updateOne(
        new Document("_id", AccountLifecycleUseCase.digest(token)),
        new Document(
            "$set", new Document("expiresAt", Date.from(clock.instant().plusMillis(ttlMillis)))),
        new UpdateOptions().upsert(true));
  }
}
