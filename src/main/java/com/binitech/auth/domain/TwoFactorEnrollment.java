package com.binitech.auth.domain;

public record TwoFactorEnrollment(String secret, String pendingSecret, long lastCounter) {
  public boolean enabled() {
    return secret != null && !secret.isBlank();
  }
}
