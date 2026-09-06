package com.binitech.auth.application.ports.outbound;

import com.binitech.auth.domain.AccessTokenClaims;
import com.binitech.auth.domain.Identity;

public interface AccessTokenPort {
  String issue(Identity identity, long sessionVersion);

  /** Validates signature and expiration, or throws InvalidCredentialsException. */
  AccessTokenClaims parse(String token);
}
