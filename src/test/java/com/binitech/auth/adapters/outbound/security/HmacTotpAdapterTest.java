package com.binitech.auth.adapters.outbound.security;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class HmacTotpAdapterTest {
  private static final String SHA256_SEED = base64("12345678901234567890123456789012");
  private static final String SHA512_SEED =
      base64("1234567890123456789012345678901234567890123456789012345678901234");

  private static String base64(String value) {
    return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.US_ASCII));
  }

  @ParameterizedTest
  @CsvSource({
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
    var adapter = new HmacTotpAdapter(algorithm, 8, 30, 0, "BiniTech");
    String seed = algorithm.equals("SHA256") ? SHA256_SEED : SHA512_SEED;

    var counter = adapter.verify(seed, code, Instant.ofEpochSecond(time));

    assertTrue(counter.isPresent());
    assertEquals(time / 30, counter.getAsLong());
  }

  @Test
  void acceptsAdjacentStepsOnlyInsideConfiguredWindow() {
    var tolerant = new HmacTotpAdapter("SHA512", 8, 30, 1, "BiniTech");
    var strict = new HmacTotpAdapter("SHA512", 8, 30, 0, "BiniTech");
    Instant nextStep = Instant.ofEpochSecond(89);

    assertEquals(1L, tolerant.verify(SHA512_SEED, "90693936", nextStep).getAsLong());
    assertTrue(strict.verify(SHA512_SEED, "90693936", nextStep).isEmpty());
  }

  @Test
  void rejectsWrongCodesLengthsAndMalformedSecrets() {
    var adapter = new HmacTotpAdapter("SHA512", 8, 30, 1, "BiniTech");
    Instant at = Instant.ofEpochSecond(59);

    assertTrue(adapter.verify(SHA512_SEED, "90693937", at).isEmpty());
    assertTrue(adapter.verify(SHA512_SEED, "906939", at).isEmpty());
    assertTrue(adapter.verify("not base64!", "90693936", at).isEmpty());
    assertTrue(adapter.verify(null, "90693936", at).isEmpty());
  }

  @Test
  void provisionCreatesBase64KeySizedForAlgorithmAndOtpauthUri() {
    var sha512 = new HmacTotpAdapter("sha-512", 6, 30, 1, "BiniTech PDV").provision("ana");
    var sha256 = new HmacTotpAdapter("SHA256", 6, 60, 1, "BiniTech").provision("ana");

    assertEquals(64, Base64.getDecoder().decode(sha512.secret()).length);
    assertEquals(32, Base64.getDecoder().decode(sha256.secret()).length);
    assertEquals("SHA512", sha512.algorithm());
    assertTrue(sha512.otpauthUri().startsWith("otpauth://totp/BiniTech%20PDV%3Aana?secret="));
    assertTrue(sha512.otpauthUri().endsWith("&algorithm=SHA512&digits=6&period=30"));
    assertTrue(sha256.otpauthUri().endsWith("&algorithm=SHA256&digits=6&period=60"));
  }

  @Test
  void rejectsInvalidConfiguration() {
    assertThrows(
        IllegalArgumentException.class, () -> new HmacTotpAdapter("SHA1", 6, 30, 1, "BiniTech"));
    assertThrows(
        IllegalArgumentException.class, () -> new HmacTotpAdapter("SHA512", 5, 30, 1, "BiniTech"));
    assertThrows(
        IllegalArgumentException.class, () -> new HmacTotpAdapter("SHA512", 6, 0, 1, "BiniTech"));
    assertThrows(
        IllegalArgumentException.class, () -> new HmacTotpAdapter("SHA512", 6, 30, -1, "BiniTech"));
  }
}
