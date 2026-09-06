package com.binitech.auth.application.ports.inbound;

import com.binitech.auth.domain.AuthResult;
import com.binitech.auth.domain.SessionIdentity;

public interface AuthenticationUseCase {
  AuthResult login(String username, String password, String tenantId);

  AuthResult refresh(String refreshToken);

  SessionIdentity session(String accessToken);

  void logout(String accessToken);
}
