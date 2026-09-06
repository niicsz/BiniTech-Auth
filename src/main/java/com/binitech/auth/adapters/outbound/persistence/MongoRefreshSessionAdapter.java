package com.binitech.auth.adapters.outbound.persistence;

import com.binitech.auth.adapters.outbound.persistence.document.RefreshSessionDocument;
import com.binitech.auth.application.ports.outbound.RefreshSessionRepositoryPort;
import com.binitech.auth.domain.RefreshSession;
import java.util.Optional;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Repository;

@Repository
public class MongoRefreshSessionAdapter implements RefreshSessionRepositoryPort {
  private final MongoTemplate mongo;

  public MongoRefreshSessionAdapter(MongoTemplate mongo) {
    this.mongo = mongo;
  }

  @Override
  public void save(RefreshSession session) {
    mongo.insert(RefreshSessionDocument.fromDomain(session));
  }

  @Override
  public Optional<RefreshSession> consume(String token) {
    return Optional.ofNullable(
            mongo.findAndRemove(
                Query.query(Criteria.where("token").is(token)), RefreshSessionDocument.class))
        .map(RefreshSessionDocument::toDomain);
  }

  @Override
  public void deleteForUser(String userId, String tenantId) {
    mongo.remove(
        Query.query(Criteria.where("userId").is(userId).and("tenantId").is(tenantId)),
        RefreshSessionDocument.class);
  }
}
