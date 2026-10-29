package com.binitech.auth.domain.exception;

public class InvalidTwoFactorCodeException extends RuntimeException {
  public InvalidTwoFactorCodeException() {
    super("Código de verificação inválido.");
  }
}
