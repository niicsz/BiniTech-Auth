package com.binitech.auth.adapters.outbound.security;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashSet;
import org.junit.jupiter.api.Test;

class HmacRecoveryCodeAdapterTest {
  private final HmacRecoveryCodeAdapter adapter = new HmacRecoveryCodeAdapter("test-pepper");

  @Test
  void generatesTenDistinctReadableCodes() {
    var codes = adapter.generate();

    assertEquals(10, codes.size());
    assertEquals(10, new HashSet<>(codes).size());
    codes.forEach(code -> assertTrue(code.matches("[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}"), code));
  }

  @Test
  void digestIsNormalizedPepperedAndNeverTheCode() {
    var digest = adapter.digest("ABCDE-FGHJK").orElseThrow();

    assertEquals(digest, adapter.digest(" abcde fghjk ").orElseThrow());
    assertEquals(digest, adapter.digest("ABCDEFGHJK").orElseThrow());
    assertFalse(digest.contains("ABCDE"));
    assertEquals(64, digest.length());
    assertNotEquals(
        digest, new HmacRecoveryCodeAdapter("other-pepper").digest("ABCDE-FGHJK").orElseThrow());
  }

  @Test
  void ignoresTotpCodesAndMalformedInput() {
    assertTrue(adapter.digest("123456").isEmpty());
    assertTrue(adapter.digest("12345678").isEmpty());
    assertTrue(adapter.digest("ABCDE-FGHJ0").isEmpty());
    assertTrue(adapter.digest("ABCDE-FGHJKL").isEmpty());
    assertTrue(adapter.digest(null).isEmpty());
    assertThrows(IllegalArgumentException.class, () -> new HmacRecoveryCodeAdapter(" "));
  }
}
