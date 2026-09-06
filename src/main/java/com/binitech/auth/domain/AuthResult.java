package com.binitech.auth.domain;

public record AuthResult(
    String accessToken, String refreshToken, String username, String role, String tenantId) {}
