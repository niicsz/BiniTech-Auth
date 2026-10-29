package com.binitech.auth.adapters.outbound.security;

import com.binitech.auth.application.ports.outbound.TotpPort;
import com.binitech.auth.domain.TwoFactorSetup;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.OptionalLong;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class HmacTotpAdapter implements TotpPort {
  private static final int[] POWERS = {
    1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000
  };
  private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  private final SecureRandom random = new SecureRandom();
  private final TotpAlgorithm algorithm;
  private final int digits;
  private final long period;
  private final int window;
  private final String issuer;

  public HmacTotpAdapter(
      @Value("${totp.algorithm:SHA512}") String algorithm,
      @Value("${totp.digits:6}") int digits,
      @Value("${totp.period:30}") long period,
      @Value("${totp.window:1}") int window,
      @Value("${totp.issuer:BiniTech}") String issuer) {
    if (digits < 6 || digits > 8) {
      throw new IllegalArgumentException("AUTH_TOTP_DIGITS deve estar entre 6 e 8.");
    }
    if (period <= 0) {
      throw new IllegalArgumentException("AUTH_TOTP_PERIOD deve ser positivo.");
    }
    if (window < 0 || window > 5) {
      throw new IllegalArgumentException("AUTH_TOTP_WINDOW deve estar entre 0 e 5.");
    }
    if (issuer == null || issuer.isBlank()) {
      throw new IllegalArgumentException("AUTH_TOTP_ISSUER é obrigatório.");
    }
    this.algorithm = TotpAlgorithm.parse(algorithm);
    this.digits = digits;
    this.period = period;
    this.window = window;
    this.issuer = issuer;
  }

  @Override
  public TwoFactorSetup provision(String accountName) {
    byte[] key = new byte[algorithm.keyLength()];
    random.nextBytes(key);
    return new TwoFactorSetup(
        Base64.getEncoder().encodeToString(key),
        uri(key, accountName),
        algorithm.name(),
        digits,
        period);
  }

  @Override
  public OptionalLong verify(String secret, String code, Instant now) {
    if (secret == null || code == null || code.length() != digits) {
      return OptionalLong.empty();
    }
    byte[] key;
    try {
      key = Base64.getDecoder().decode(secret);
    } catch (IllegalArgumentException exception) {
      return OptionalLong.empty();
    }
    byte[] supplied = code.getBytes(StandardCharsets.US_ASCII);
    long current = Math.floorDiv(now.getEpochSecond(), period);
    for (long counter = current - window; counter <= current + window; counter++) {
      if (counter >= 0
          && MessageDigest.isEqual(
              generate(key, counter).getBytes(StandardCharsets.US_ASCII), supplied)) {
        return OptionalLong.of(counter);
      }
    }
    return OptionalLong.empty();
  }

  private String generate(byte[] key, long counter) {
    byte[] hash = hmac(key, ByteBuffer.allocate(Long.BYTES).putLong(counter).array());
    int offset = hash[hash.length - 1] & 0x0f;
    int binary =
        ((hash[offset] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8)
            | (hash[offset + 3] & 0xff);
    String otp = Integer.toString(binary % POWERS[digits]);
    return "0".repeat(digits - otp.length()) + otp;
  }

  private byte[] hmac(byte[] key, byte[] message) {
    try {
      Mac mac = Mac.getInstance(algorithm.mac());
      mac.init(new SecretKeySpec(key, algorithm.mac()));
      return mac.doFinal(message);
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException(exception);
    }
  }

  private String uri(byte[] key, String accountName) {
    return "otpauth://totp/"
        + encode(issuer + ":" + accountName)
        + "?secret="
        + base32(key)
        + "&issuer="
        + encode(issuer)
        + "&algorithm="
        + algorithm.name()
        + "&digits="
        + digits
        + "&period="
        + period;
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private static String base32(byte[] data) {
    StringBuilder out = new StringBuilder();
    int buffer = 0;
    int bits = 0;
    for (byte value : data) {
      buffer = (buffer << 8) | (value & 0xff);
      bits += 8;
      while (bits >= 5) {
        out.append(BASE32.charAt((buffer >> (bits - 5)) & 31));
        bits -= 5;
      }
    }
    if (bits > 0) {
      out.append(BASE32.charAt((buffer << (5 - bits)) & 31));
    }
    return out.toString();
  }
}
