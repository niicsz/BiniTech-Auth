package com.binitech.auth.adapters.inbound.web;

import com.binitech.auth.domain.exception.InvalidCredentialsException;

final class BearerToken {
  private BearerToken() {}

  static String extract(String authorization) {
    if (authorization == null
        || !authorization.startsWith("Bearer ")
        || authorization.substring(7).isBlank()) {
      throw new InvalidCredentialsException();
    }
    return authorization.substring(7);
  }
}
