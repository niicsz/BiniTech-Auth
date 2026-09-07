package com.binitech.auth.application.ports.outbound;

import com.binitech.auth.domain.RefreshSession;
import java.util.Optional;

public interface RefreshSessionRepositoryPort {
  void save(RefreshSession session);

  Optional<RefreshSession> consume(String token);

  void deleteForUser(String userId, String tenantId);
}
