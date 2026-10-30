package com.binitech.auth.adapters.outbound.security;

import com.binitech.auth.application.ports.outbound.RecoveryCodePort;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.IntStream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class HmacRecoveryCodeAdapter implements RecoveryCodePort {
  static final int CODES = 10;
  static final int LENGTH = 10;
  private static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  private static final byte[] CONTEXT =
      "binitech-auth:recovery-code:v1".getBytes(StandardCharsets.US_ASCII);

  private final SecureRandom random = new SecureRandom();
  private final SecretKeySpec key;

  public HmacRecoveryCodeAdapter(@Value("${security.pepper}") String pepper) {
    if (pepper == null || pepper.isBlank()) {
      throw new IllegalArgumentException("SECURITY_PEPPER é obrigatório.");
    }
    this.key =
        new SecretKeySpec(
            hmac(new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), "HmacSHA256"), CONTEXT),
            "HmacSHA256");
  }

  @Override
  public List<String> generate() {
    return IntStream.range(0, CODES).mapToObj(i -> code()).toList();
  }

  @Override
  public Optional<String> digest(String code) {
    if (code == null) {
      return Optional.empty();
    }
    String normalized = code.replace("-", "").replace(" ", "").toUpperCase(Locale.ROOT);
    if (normalized.length() != LENGTH
        || !normalized.chars().allMatch(c -> ALPHABET.indexOf(c) >= 0)) {
      return Optional.empty();
    }
    return Optional.of(
        HexFormat.of().formatHex(hmac(key, normalized.getBytes(StandardCharsets.US_ASCII))));
  }

  private String code() {
    StringBuilder out = new StringBuilder(LENGTH + 1);
    for (int i = 0; i < LENGTH; i++) {
      if (i == LENGTH / 2) {
        out.append('-');
      }
      out.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
    }
    return out.toString();
  }

  private static byte[] hmac(SecretKeySpec key, byte[] message) {
    try {
      Mac mac = Mac.getInstance(key.getAlgorithm());
      mac.init(key);
      return mac.doFinal(message);
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException(exception);
    }
  }
}
