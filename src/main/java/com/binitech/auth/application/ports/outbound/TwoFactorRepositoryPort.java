package com.binitech.auth.application.ports.outbound;

import com.binitech.auth.domain.TwoFactorEnrollment;
import java.util.Optional;

public interface TwoFactorRepositoryPort {
  Optional<TwoFactorEnrollment> find(String userId);

  boolean savePending(String userId, String secret);

  boolean activate(String userId, String pendingSecret, long counter);

  boolean markUsed(String userId, long counter);

  boolean disable(String userId, String secret, long counter);
}
