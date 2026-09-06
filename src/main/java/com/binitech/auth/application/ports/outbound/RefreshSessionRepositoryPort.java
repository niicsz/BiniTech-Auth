package com.binitech.auth.application.ports.outbound;

import com.binitech.auth.domain.RefreshSession;
import java.util.Optional;

public interface RefreshSessionRepositoryPort {
  void save(RefreshSession session);

  /** Atomically removes and returns a session; a token can be consumed at most once. */
  Optional<RefreshSession> consume(String token);

  void deleteForUser(String userId, String tenantId);
}
