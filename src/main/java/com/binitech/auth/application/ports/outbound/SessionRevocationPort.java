package com.binitech.auth.application.ports.outbound;

public interface SessionRevocationPort {
  long sessionVersion(String userId);

  boolean isBlacklisted(String accessToken);

  void blacklist(String accessToken, long ttlMillis);

  default void revoke(String userId) {
    throw new UnsupportedOperationException();
  }
}
