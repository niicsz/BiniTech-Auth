package com.binitech.auth.application.ports.inbound;

import com.binitech.auth.domain.TwoFactorSetup;
import com.binitech.auth.domain.TwoFactorStatus;

public interface TwoFactorManagement {
  TwoFactorStatus status(String accessToken);

  TwoFactorSetup setup(String accessToken);

  void enable(String accessToken, String code);

  void disable(String accessToken, String code);
}
