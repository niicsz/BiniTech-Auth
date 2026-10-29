package com.binitech.auth.domain.exception;

public class TwoFactorConflictException extends RuntimeException {
  public TwoFactorConflictException() {
    super("Estado do segundo fator não permite esta operação.");
  }
}
