package com.binitech.auth.adapters.inbound.web;

final class TwoFactorCode {
  static final String PATTERN = "\\d{6,8}|[A-Za-z0-9]{5}-?[A-Za-z0-9]{5}";

  private TwoFactorCode() {}
}
