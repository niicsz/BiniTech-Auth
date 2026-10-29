package com.binitech.auth.domain.exception;

import java.time.Instant;

public class TwoFactorLockedException extends RuntimeException {
  private final Instant lockedUntil;

  public TwoFactorLockedException(Instant lockedUntil) {
    super("Usuário bloqueado por excesso de tentativas inválidas.");
    this.lockedUntil = lockedUntil;
  }

  public Instant lockedUntil() {
    return lockedUntil;
  }
}
