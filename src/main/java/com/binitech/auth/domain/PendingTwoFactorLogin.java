package com.binitech.auth.domain;

import java.time.Instant;

public record PendingTwoFactorLogin(
    String id, String userId, String tenantId, long sessionVersion, Instant expiresAt) {}
