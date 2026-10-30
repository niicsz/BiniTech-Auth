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
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.OptionalLong;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class HmacTotpAdapter implements TotpPort {
  private static final int[] POWERS = {
    1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000
  };
  private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  private static final String SEALED_PREFIX = "v1:";
  private static final byte[] SEAL_CONTEXT =
      "binitech-auth:totp-secret:v1".getBytes(StandardCharsets.US_ASCII);
  private static final int IV_LENGTH = 12;
  private static final int TAG_BITS = 128;

  private final SecureRandom random = new SecureRandom();
  private final TotpAlgorithm algorithm;
  private final int digits;
  private final long period;
  private final int window;
  private final String issuer;
  private final SecretKeySpec sealKey;

  public HmacTotpAdapter(
      @Value("${totp.algorithm:SHA1}") String algorithm,
      @Value("${totp.digits:6}") int digits,
      @Value("${totp.period:30}") long period,
      @Value("${totp.window:1}") int window,
      @Value("${totp.issuer:BiniTech}") String issuer,
      @Value("${security.pepper}") String pepper) {
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
    if (pepper == null || pepper.isBlank()) {
      throw new IllegalArgumentException("SECURITY_PEPPER é obrigatório.");
    }
    this.algorithm = TotpAlgorithm.parse(algorithm);
    this.digits = digits;
    this.period = period;
    this.window = window;
    this.issuer = issuer;
    this.sealKey =
        new SecretKeySpec(
            mac(
                new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), "HmacSHA256"),
                SEAL_CONTEXT),
            "AES");
  }

  @Override
  public TwoFactorSetup provision(String accountName) {
    byte[] key = new byte[algorithm.keyLength()];
    random.nextBytes(key);
    return new TwoFactorSetup(
        seal(algorithm, key), uri(key, accountName), algorithm.name(), digits, period);
  }

  @Override
  public OptionalLong verify(String secret, String code, Instant now) {
    if (secret == null || code == null || code.length() != digits) {
      return OptionalLong.empty();
    }
    Optional<SecretKeySpec> key = unseal(secret);
    if (key.isEmpty()) {
      return OptionalLong.empty();
    }
    byte[] supplied = code.getBytes(StandardCharsets.US_ASCII);
    long current = Math.floorDiv(now.getEpochSecond(), period);
    for (long counter = current - window; counter <= current + window; counter++) {
      if (counter >= 0
          && MessageDigest.isEqual(
              generate(key.get(), counter).getBytes(StandardCharsets.US_ASCII), supplied)) {
        return OptionalLong.of(counter);
      }
    }
    return OptionalLong.empty();
  }

  String seal(TotpAlgorithm keyAlgorithm, byte[] key) {
    byte[] plain =
        (keyAlgorithm.name() + ":" + Base64.getEncoder().encodeToString(key))
            .getBytes(StandardCharsets.US_ASCII);
    byte[] iv = new byte[IV_LENGTH];
    random.nextBytes(iv);
    byte[] encrypted = cipher(Cipher.ENCRYPT_MODE, iv, plain);
    byte[] out = ByteBuffer.allocate(iv.length + encrypted.length).put(iv).put(encrypted).array();
    return SEALED_PREFIX + Base64.getEncoder().encodeToString(out);
  }

  private Optional<SecretKeySpec> unseal(String secret) {
    try {
      if (!secret.startsWith(SEALED_PREFIX)) {
        return Optional.of(new SecretKeySpec(Base64.getDecoder().decode(secret), algorithm.mac()));
      }
      byte[] data = Base64.getDecoder().decode(secret.substring(SEALED_PREFIX.length()));
      if (data.length <= IV_LENGTH) {
        return Optional.empty();
      }
      byte[] iv = Arrays.copyOf(data, IV_LENGTH);
      byte[] encrypted = Arrays.copyOfRange(data, IV_LENGTH, data.length);
      String plain =
          new String(cipher(Cipher.DECRYPT_MODE, iv, encrypted), StandardCharsets.US_ASCII);
      int separator = plain.indexOf(':');
      if (separator < 0) {
        return Optional.empty();
      }
      return Optional.of(
          new SecretKeySpec(
              Base64.getDecoder().decode(plain.substring(separator + 1)),
              TotpAlgorithm.parse(plain.substring(0, separator)).mac()));
    } catch (IllegalArgumentException | IllegalStateException exception) {
      return Optional.empty();
    }
  }

  private byte[] cipher(int mode, byte[] iv, byte[] input) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(mode, sealKey, new GCMParameterSpec(TAG_BITS, iv));
      cipher.updateAAD(SEAL_CONTEXT);
      return cipher.doFinal(input);
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException(exception);
    }
  }

  private String generate(SecretKeySpec key, long counter) {
    byte[] hash = mac(key, ByteBuffer.allocate(Long.BYTES).putLong(counter).array());
    int offset = hash[hash.length - 1] & 0x0f;
    int binary =
        ((hash[offset] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8)
            | (hash[offset + 3] & 0xff);
    String otp = Integer.toString(binary % POWERS[digits]);
    return "0".repeat(digits - otp.length()) + otp;
  }

  private static byte[] mac(SecretKeySpec key, byte[] message) {
    try {
      Mac mac = Mac.getInstance(key.getAlgorithm());
      mac.init(key);
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
