package com.binitech.auth.domain;

public record Account(
    String id,
    String username,
    String password,
    String tenantId,
    boolean active,
    boolean managedCredential,
    String recoveryEmail) {}
