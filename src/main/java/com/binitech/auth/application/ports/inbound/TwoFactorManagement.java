package com.binitech.auth.application.ports.inbound;

import com.binitech.auth.domain.TwoFactorSetup;
import com.binitech.auth.domain.TwoFactorStatus;
import java.util.List;

public interface TwoFactorManagement {
  TwoFactorStatus status(String accessToken);

  TwoFactorSetup setup(String accessToken);

  List<String> enable(String accessToken, String code);

  List<String> regenerateRecoveryCodes(String accessToken, String code);

  void disable(String accessToken, String code);

  boolean reset(String identityId);
}
