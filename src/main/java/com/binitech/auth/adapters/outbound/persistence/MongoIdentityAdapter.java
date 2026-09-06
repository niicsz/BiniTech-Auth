package com.binitech.auth.adapters.outbound.persistence;

import com.binitech.auth.adapters.outbound.persistence.document.IdentityDocument;
import com.binitech.auth.application.ports.outbound.IdentityRepositoryPort;
import com.binitech.auth.domain.Identity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Repository;

@Repository
public class MongoIdentityAdapter implements IdentityRepositoryPort {
  private final MongoTemplate mongo;

  public MongoIdentityAdapter(MongoTemplate mongo) {
    this.mongo = mongo;
  }

  @Override
  public List<Identity> findCandidates(String username, String tenantId) {
    Criteria criteria = Criteria.where("username").is(username);
    if (tenantId != null && !tenantId.isBlank()) criteria = criteria.and("tenantId").is(tenantId);
    return mongo.find(Query.query(criteria), IdentityDocument.class).stream()
        .map(IdentityDocument::toDomain)
        .toList();
  }

  @Override
  public Optional<Identity> findById(String id) {
    return Optional.ofNullable(mongo.findById(id, IdentityDocument.class))
        .map(IdentityDocument::toDomain);
  }
}
