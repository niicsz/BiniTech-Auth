package com.binitech.auth.application.ports.inbound;

import com.binitech.auth.domain.RecoveryDelivery;
import java.util.Optional;

public interface AccountLifecycle {
  void provision(
      String identityId, String username, String password, String tenantId, String recoveryEmail);

  void changePassword(String identityId, String currentPassword, String newPassword);

  Optional<RecoveryDelivery> requestRecovery(String username);

  void completeRecovery(String token, String newPassword);

  void revokeSessions(String identityId);
}
