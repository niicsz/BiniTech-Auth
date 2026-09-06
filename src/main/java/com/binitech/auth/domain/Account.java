package com.binitech.auth.domain;

/** Identity data only. Application roles and memberships are not authentication data. */
public record Account(
    String id,
    String username,
    String password,
    String tenantId,
    boolean active,
    boolean managedCredential,
    String recoveryEmail) {}
