package com.binitech.auth.domain;

import java.time.Instant;

public record TwoFactorStatus(boolean enabled, Instant lockedUntil, int recoveryCodesRemaining) {}
