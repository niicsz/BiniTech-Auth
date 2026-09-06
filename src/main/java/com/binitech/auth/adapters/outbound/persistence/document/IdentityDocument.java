package com.binitech.auth.adapters.outbound.persistence.document;

import com.binitech.auth.domain.Identity;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document("users")
public record IdentityDocument(
    @Id String id, String username, String password, String role, String tenantId, Boolean active) {
  public Identity toDomain() {
    return new Identity(id, username, password, role, tenantId, active);
  }
}
