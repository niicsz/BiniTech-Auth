package com.binitech.auth.application.usecases;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

final class LoginThrottle {
  private static final int MAX_TRACKED = 100_000;

  private final int maxFailures;
  private final Duration window;
  private final Clock clock;
  private final Map<String, Failures> failures = new ConcurrentHashMap<>();

  LoginThrottle(int maxFailures, Duration window, Clock clock) {
    this.maxFailures = maxFailures;
    this.window = window;
    this.clock = clock;
  }

  boolean isLocked(String username, String tenantId) {
    Failures current = failures.get(key(username, tenantId));
    return current != null && current.count() >= maxFailures && !expired(current);
  }

  void registerFailure(String username, String tenantId) {
    if (failures.size() >= MAX_TRACKED) {
      failures.values().removeIf(this::expired);
      if (failures.size() >= MAX_TRACKED) {
        failures.clear();
      }
    }
    Instant now = clock.instant();
    failures.compute(
        key(username, tenantId),
        (k, current) ->
            current == null || expired(current)
                ? new Failures(1, now)
                : new Failures(current.count() + 1, current.since()));
  }

  void reset(String username, String tenantId) {
    failures.remove(key(username, tenantId));
  }

  private boolean expired(Failures current) {
    return current.since().plus(window).isBefore(clock.instant());
  }

  private static String key(String username, String tenantId) {
    String user = username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    return user + "|" + (tenantId == null ? "" : tenantId.trim());
  }

  private record Failures(int count, Instant since) {}
}
