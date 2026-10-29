package com.binitech.auth.domain;

import java.time.Instant;

public record TwoFactorChallenge(String challengeToken, Instant expiresAt)
    implements LoginOutcome {}
