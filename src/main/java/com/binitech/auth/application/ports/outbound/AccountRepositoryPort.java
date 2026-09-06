package com.binitech.auth.application.ports.outbound;

import com.binitech.auth.domain.Account;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface AccountRepositoryPort {
  Optional<Account> find(String id);

  List<Account> findByUsername(String username);

  /** Insert once; a retry must not replace credentials or another identity. */
  Account provision(Account account);

  /** Atomically changes credentials, increments the session version and clears recovery tokens. */
  boolean changePassword(String id, String expectedHash, String replacementHash);

  void requestRecovery(String id, String expectedHash, String tokenDigest, Instant expiresAt);

  boolean completeRecovery(String tokenDigest, String replacementHash, Instant now);
}
