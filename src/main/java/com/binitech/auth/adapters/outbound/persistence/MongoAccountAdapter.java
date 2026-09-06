package com.binitech.auth.adapters.outbound.persistence;

import com.binitech.auth.application.ports.outbound.AccountRepositoryPort;
import com.binitech.auth.domain.Account;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.ReturnDocument;
import java.time.Instant;
import java.util.*;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class MongoAccountAdapter implements AccountRepositoryPort {
  private final MongoCollection<Document> identities;
  private final String application;

  public MongoAccountAdapter(
      MongoTemplate mongo, @Value("${auth.application-id:pdv}") String application) {
    this.identities = mongo.getCollection("identities");
    this.application = application;
  }

  private Document scope() {
    return new Document("applicationId", application);
  }

  public Optional<Account> find(String id) {
    return Optional.ofNullable(identities.find(scope().append("_id", id)).first()).map(this::map);
  }

  public List<Account> findByUsername(String username) {
    return identities.find(scope().append("username", username)).into(new ArrayList<>()).stream()
        .map(this::map)
        .toList();
  }

  public Account provision(Account a) {
    // Raw driver keeps legacy ObjectId-shaped identity strings as strings.
    Document fields =
        new Document("username", a.username())
            .append("password", a.password())
            .append("tenantId", a.tenantId())
            .append("active", a.active())
            .append("managedCredential", a.managedCredential())
            .append("recoveryEmail", a.recoveryEmail())
            .append("sessionVersion", 0L);
    Document result =
        identities.findOneAndUpdate(
            scope().append("_id", a.id()),
            new Document("$setOnInsert", fields),
            new FindOneAndUpdateOptions().upsert(true).returnDocument(ReturnDocument.AFTER));
    return map(result);
  }

  private Document passwordUpdate(String hash) {
    return new Document(
            "$set", new Document("password", hash).append("updatedAt", Date.from(Instant.now())))
        .append("$inc", new Document("sessionVersion", 1L))
        .append("$unset", new Document("recoveryDigest", "").append("recoveryExpiresAt", ""));
  }

  private Document mutable() {
    return scope()
        .append("active", new Document("$ne", false))
        .append("managedCredential", new Document("$ne", true));
  }

  public boolean changePassword(String id, String expectedHash, String replacementHash) {
    return identities
            .updateOne(
                mutable().append("_id", id).append("password", expectedHash),
                passwordUpdate(replacementHash))
            .getModifiedCount()
        == 1;
  }

  public void requestRecovery(String id, String expectedHash, String digest, Instant expiresAt) {
    identities.updateOne(
        mutable().append("_id", id).append("password", expectedHash),
        new Document(
            "$set",
            new Document("recoveryDigest", digest)
                .append("recoveryExpiresAt", Date.from(expiresAt))));
  }

  public boolean completeRecovery(String digest, String replacementHash, Instant now) {
    return identities
            .updateOne(
                mutable()
                    .append("recoveryDigest", digest)
                    .append("recoveryExpiresAt", new Document("$gt", Date.from(now))),
                passwordUpdate(replacementHash))
            .getModifiedCount()
        == 1;
  }

  private Account map(Document d) {
    return new Account(
        d.getString("_id"),
        d.getString("username"),
        d.getString("password"),
        d.getString("tenantId"),
        !Boolean.FALSE.equals(d.getBoolean("active")),
        Boolean.TRUE.equals(d.getBoolean("managedCredential")),
        d.getString("recoveryEmail"));
  }
}
