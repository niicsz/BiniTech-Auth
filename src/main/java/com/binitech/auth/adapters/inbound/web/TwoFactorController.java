package com.binitech.auth.adapters.inbound.web;

import com.binitech.auth.application.ports.inbound.TwoFactorManagement;
import com.binitech.auth.domain.TwoFactorSetup;
import com.binitech.auth.domain.TwoFactorStatus;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/two-factor")
public class TwoFactorController {
  private final TwoFactorManagement twoFactor;

  public TwoFactorController(TwoFactorManagement twoFactor) {
    this.twoFactor = twoFactor;
  }

  @GetMapping
  public TwoFactorStatus status(
      @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
    return twoFactor.status(BearerToken.extract(authorization));
  }

  @PostMapping("/setup")
  public TwoFactorSetup setup(
      @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
    return twoFactor.setup(BearerToken.extract(authorization));
  }

  @PostMapping("/enable")
  public ResponseEntity<Void> enable(
      @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
      @Valid @RequestBody CodeRequest request) {
    twoFactor.enable(BearerToken.extract(authorization), request.code());
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/disable")
  public ResponseEntity<Void> disable(
      @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
      @Valid @RequestBody CodeRequest request) {
    twoFactor.disable(BearerToken.extract(authorization), request.code());
    return ResponseEntity.noContent().build();
  }

  public record CodeRequest(@NotBlank @Pattern(regexp = "\\d{6,8}") String code) {}
}
