package com.binitech.auth.application.ports.inbound;

import com.binitech.auth.domain.TwoFactorSetup;

public interface TwoFactorManagement {
  TwoFactorSetup setup(String accessToken);

  void enable(String accessToken, String code);

  void disable(String accessToken, String code);
}
