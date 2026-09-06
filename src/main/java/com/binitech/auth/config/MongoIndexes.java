package com.binitech.auth.config;

import com.mongodb.client.model.IndexOptions;
import java.util.concurrent.TimeUnit;
import org.bson.Document;
import org.springframework.boot.CommandLineRunner;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Component;

@Component
public class MongoIndexes implements CommandLineRunner {
  private final MongoTemplate mongo;

  public MongoIndexes(MongoTemplate mongo) {
    this.mongo = mongo;
  }

  public void run(String... args) {
    mongo
        .getCollection("identities")
        .createIndex(
            new Document("applicationId", 1).append("tenantId", 1).append("username", 1),
            new IndexOptions().unique(true).name("identity_login_unique"));
    mongo
        .getCollection("revoked_tokens")
        .createIndex(
            new Document("expiresAt", 1), new IndexOptions().expireAfter(0L, TimeUnit.SECONDS));
  }
}
