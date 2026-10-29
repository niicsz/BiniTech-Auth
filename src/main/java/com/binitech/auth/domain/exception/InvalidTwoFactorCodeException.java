package com.binitech.auth.domain.exception;

public class InvalidTwoFactorCodeException extends RuntimeException {
  private final Integer remainingAttempts;

  public InvalidTwoFactorCodeException() {
    this(null);
  }

  public InvalidTwoFactorCodeException(Integer remainingAttempts) {
    super("Código de verificação inválido.");
    this.remainingAttempts = remainingAttempts;
  }

  public Integer remainingAttempts() {
    return remainingAttempts;
  }
}
