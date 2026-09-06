package com.binitech.auth.domain;

public record Identity(
    String id, String username, String password, String role, String tenantId, Boolean active) {
  public boolean isActive() {
    return !Boolean.FALSE.equals(active);
  }
}
