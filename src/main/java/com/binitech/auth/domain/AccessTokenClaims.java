package com.binitech.auth.domain;

import java.time.Instant;

public record AccessTokenClaims(String userId, long sessionVersion, Instant expiresAt) {}
