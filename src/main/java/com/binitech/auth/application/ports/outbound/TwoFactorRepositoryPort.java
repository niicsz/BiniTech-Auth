package com.binitech.auth.application.ports.outbound;

import com.binitech.auth.domain.TwoFactorEnrollment;
import com.binitech.auth.domain.TwoFactorFailure;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface TwoFactorRepositoryPort {
  Optional<TwoFactorEnrollment> find(String userId);

  boolean savePending(String userId, String secret);

  boolean activate(String userId, String pendingSecret, long counter, List<String> recoveryCodes);

  boolean markUsed(String userId, long counter);

  boolean useRecoveryCode(String userId, String secret, String recoveryCode);

  boolean replaceRecoveryCodes(String userId, String secret, List<String> recoveryCodes);

  boolean disable(String userId, String secret);

  boolean reset(String userId);

  TwoFactorFailure registerFailure(String userId, int maxFailures, Instant lockUntil);
}
