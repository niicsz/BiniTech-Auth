package com.binitech.auth.application.ports.outbound;

import com.binitech.auth.domain.TwoFactorSetup;
import java.time.Instant;
import java.util.OptionalLong;

public interface TotpPort {
  TwoFactorSetup provision(String accountName);

  OptionalLong verify(String secret, String code, Instant now);
}
