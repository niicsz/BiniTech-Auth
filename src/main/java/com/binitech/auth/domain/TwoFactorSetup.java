package com.binitech.auth.domain;

public record TwoFactorSetup(
    String secret, String otpauthUri, String algorithm, int digits, long period) {}
