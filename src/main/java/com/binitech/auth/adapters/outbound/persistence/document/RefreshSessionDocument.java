package com.binitech.auth.adapters.outbound.persistence.document;

import com.binitech.auth.domain.RefreshSession;
import java.time.Instant;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Document("refresh_tokens")
public record RefreshSessionDocument(
    @Id String id,
    @Indexed(unique = true) String token,
    String userId,
    String tenantId,
    @Indexed(expireAfter = "0s") Instant expiryDate,
    Long sessionVersion) {
  public RefreshSession toDomain() {
    return new RefreshSession(id, token, userId, tenantId, expiryDate, sessionVersion);
  }

  public static RefreshSessionDocument fromDomain(RefreshSession session) {
    return new RefreshSessionDocument(
        session.id(),
        session.token(),
        session.userId(),
        session.tenantId(),
        session.expiryDate(),
        session.sessionVersion());
  }
}
