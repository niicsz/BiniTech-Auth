package com.binitech.auth.adapters.outbound.security;

import java.util.Locale;

public enum TotpAlgorithm {
  SHA256("HmacSHA256", 32),
  SHA512("HmacSHA512", 64);

  private final String mac;
  private final int keyLength;

  TotpAlgorithm(String mac, int keyLength) {
    this.mac = mac;
    this.keyLength = keyLength;
  }

  public String mac() {
    return mac;
  }

  public int keyLength() {
    return keyLength;
  }

  public static TotpAlgorithm parse(String value) {
    if (value != null) {
      String normalized = value.trim().toUpperCase(Locale.ROOT).replace("-", "");
      for (TotpAlgorithm algorithm : values()) {
        if (algorithm.name().equals(normalized)) {
          return algorithm;
        }
      }
    }
    throw new IllegalArgumentException("AUTH_TOTP_ALGORITHM deve ser SHA256 ou SHA512.");
  }
}
