package com.binitech.auth.application.ports.outbound;

import com.binitech.auth.domain.PendingTwoFactorLogin;
import java.time.Instant;
import java.util.Optional;

public interface TwoFactorChallengeRepositoryPort {
  void save(PendingTwoFactorLogin challenge);

  Optional<PendingTwoFactorLogin> attempt(String id, Instant now, int maxAttempts);

  boolean consume(String id);
}
