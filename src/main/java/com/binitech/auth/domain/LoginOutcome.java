package com.binitech.auth.domain;

public sealed interface LoginOutcome permits AuthResult, TwoFactorChallenge {}
