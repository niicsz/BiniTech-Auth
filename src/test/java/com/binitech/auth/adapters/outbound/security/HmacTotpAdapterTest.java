package com.binitech.auth.adapters.outbound.security;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class HmacTotpAdapterTest {
  private static final String PEPPER = "test-pepper";
  private static final byte[] SHA1_SEED = ascii("12345678901234567890");
  private static final byte[] SHA256_SEED = ascii("12345678901234567890123456789012");
  private static final byte[] SHA512_SEED =
      ascii("1234567890123456789012345678901234567890123456789012345678901234");

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private static HmacTotpAdapter adapter(String algorithm, int digits, int window) {
    return new HmacTotpAdapter(algorithm, digits, 30, window, "BiniTech", PEPPER);
  }

  private static byte[] seed(TotpAlgorithm algorithm) {
    return switch (algorithm) {
      case SHA1 -> SHA1_SEED;
      case SHA256 -> SHA256_SEED;
      case SHA512 -> SHA512_SEED;
    };
  }

  @ParameterizedTest
  @CsvSource({
    "SHA1, 59, 94287082",
    "SHA1, 1111111109, 07081804",
    "SHA1, 1111111111, 14050471",
    "SHA1, 1234567890, 89005924",
    "SHA1, 2000000000, 69279037",
    "SHA1, 20000000000, 65353130",
    "SHA256, 59, 46119246",
    "SHA256, 1111111109, 68084774",
    "SHA256, 1111111111, 67062674",
    "SHA256, 1234567890, 91819424",
    "SHA256, 2000000000, 90698825",
    "SHA256, 20000000000, 77737706",
    "SHA512, 59, 90693936",
    "SHA512, 1111111109, 25091201",
    "SHA512, 1111111111, 99943326",
    "SHA512, 1234567890, 93441116",
    "SHA512, 2000000000, 38618901",
    "SHA512, 20000000000, 47863826"
  })
  void matchesRfc6238Vectors(String algorithm, long time, String code) {
    var adapter = adapter(algorithm, 8, 0);
    TotpAlgorithm parsed = TotpAlgorithm.parse(algorithm);
    String secret = adapter.seal(parsed, seed(parsed));

    var counter = adapter.verify(secret, code, Instant.ofEpochSecond(time));

    assertTrue(counter.isPresent());
    assertEquals(time / 30, counter.getAsLong());
  }

  @Test
  void keepsAlgorithmOfEachSecretWhenConfigurationChanges() {
    String sha512Secret = adapter("SHA512", 8, 0).seal(TotpAlgorithm.SHA512, SHA512_SEED);
    var sha1Adapter = adapter("SHA1", 8, 0);

    assertTrue(sha1Adapter.verify(sha512Secret, "90693936", Instant.ofEpochSecond(59)).isPresent());
  }

  @Test
  void acceptsAdjacentStepsOnlyInsideConfiguredWindow() {
    var tolerant = adapter("SHA512", 8, 1);
    var strict = adapter("SHA512", 8, 0);
    String secret = tolerant.seal(TotpAlgorithm.SHA512, SHA512_SEED);
    Instant nextStep = Instant.ofEpochSecond(89);

    assertEquals(1L, tolerant.verify(secret, "90693936", nextStep).getAsLong());
    assertTrue(strict.verify(secret, "90693936", nextStep).isEmpty());
  }

  @Test
  void rejectsWrongCodesLengthsAndMalformedSecrets() {
    var adapter = adapter("SHA512", 8, 1);
    String secret = adapter.seal(TotpAlgorithm.SHA512, SHA512_SEED);
    Instant at = Instant.ofEpochSecond(59);

    assertTrue(adapter.verify(secret, "90693937", at).isEmpty());
    assertTrue(adapter.verify(secret, "906939", at).isEmpty());
    assertTrue(adapter.verify("not base64!", "90693936", at).isEmpty());
    assertTrue(adapter.verify("v1:AAAA", "90693936", at).isEmpty());
    assertTrue(adapter.verify(null, "90693936", at).isEmpty());
  }

  @Test
  void storesSecretEncryptedAndBoundToPepper() {
    var adapter = adapter("SHA1", 8, 0);
    String secret = adapter.seal(TotpAlgorithm.SHA1, SHA1_SEED);
    Instant at = Instant.ofEpochSecond(59);
    byte[] sealed = Base64.getDecoder().decode(secret.substring(3));
    sealed[sealed.length - 1] ^= 1;
    String tampered = "v1:" + Base64.getEncoder().encodeToString(sealed);
    var otherPepper = new HmacTotpAdapter("SHA1", 8, 30, 0, "BiniTech", "other-pepper");

    assertTrue(secret.startsWith("v1:"));
    assertFalse(new String(sealed, StandardCharsets.ISO_8859_1).contains("SHA1"));
    assertNotEquals(secret, adapter.seal(TotpAlgorithm.SHA1, SHA1_SEED));
    assertTrue(adapter.verify(tampered, "94287082", at).isEmpty());
    assertTrue(otherPepper.verify(secret, "94287082", at).isEmpty());
  }

  @Test
  void acceptsLegacyBase64SecretsWithConfiguredAlgorithm() {
    String legacy = Base64.getEncoder().encodeToString(SHA512_SEED);

    assertTrue(
        adapter("SHA512", 8, 0).verify(legacy, "90693936", Instant.ofEpochSecond(59)).isPresent());
  }

  @Test
  void provisionCreatesSealedKeySizedForAlgorithmAndOtpauthUri() {
    var sha1 = new HmacTotpAdapter("sha-1", 6, 30, 1, "BiniTech PDV", PEPPER).provision("ana");
    var sha512 = new HmacTotpAdapter("SHA512", 6, 60, 1, "BiniTech", PEPPER).provision("ana");

    assertTrue(sha1.secret().startsWith("v1:"));
    assertEquals("SHA1", sha1.algorithm());
    assertTrue(sha1.otpauthUri().startsWith("otpauth://totp/BiniTech%20PDV%3Aana?secret="));
    assertTrue(sha1.otpauthUri().endsWith("&algorithm=SHA1&digits=6&period=30"));
    assertTrue(sha512.otpauthUri().endsWith("&algorithm=SHA512&digits=6&period=60"));
    assertEquals(32, base32Secret(sha1.otpauthUri()).length());
    assertEquals(103, base32Secret(sha512.otpauthUri()).length());
  }

  private static String base32Secret(String uri) {
    int start = uri.indexOf("secret=") + 7;
    return uri.substring(start, uri.indexOf('&', start));
  }

  @Test
  void rejectsInvalidConfiguration() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new HmacTotpAdapter("MD5", 6, 30, 1, "BiniTech", PEPPER));
    assertThrows(IllegalArgumentException.class, () -> adapter("SHA512", 5, 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> new HmacTotpAdapter("SHA512", 6, 0, 1, "BiniTech", PEPPER));
    assertThrows(IllegalArgumentException.class, () -> adapter("SHA512", 6, -1));
    assertThrows(
        IllegalArgumentException.class,
        () -> new HmacTotpAdapter("SHA512", 6, 30, 1, "BiniTech", " "));
  }
}
