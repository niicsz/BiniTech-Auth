package com.binitech.auth.domain;

public record SessionIdentity(String userId, String username, String role, String tenantId) {}
