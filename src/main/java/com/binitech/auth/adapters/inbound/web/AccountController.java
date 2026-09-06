package com.binitech.auth.adapters.inbound.web;

import com.binitech.auth.application.ports.inbound.AccountLifecycle;
import com.binitech.auth.domain.RecoveryDelivery;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/internal/identities")
public class AccountController {
  private final AccountLifecycle accounts;

  public AccountController(AccountLifecycle accounts) {
    this.accounts = accounts;
  }

  @PostMapping("/provision")
  public ResponseEntity<Void> provision(@Valid @RequestBody Provision request) {
    accounts.provision(
        request.identityId(),
        request.username(),
        request.password(),
        request.tenantId(),
        request.recoveryEmail());
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/change-password")
  public ResponseEntity<Void> changePassword(@Valid @RequestBody PasswordChange request) {
    accounts.changePassword(request.identityId(), request.currentPassword(), request.newPassword());
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/recovery")
  public ResponseEntity<RecoveryDelivery> recovery(@Valid @RequestBody Recovery request) {
    return accounts
        .requestRecovery(request.username())
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.noContent().build());
  }

  @PostMapping("/reset-password")
  public ResponseEntity<Void> reset(@Valid @RequestBody Reset request) {
    accounts.completeRecovery(request.token(), request.newPassword());
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/revoke")
  public ResponseEntity<Void> revoke(@Valid @RequestBody Revoke request) {
    accounts.revokeSessions(request.identityId());
    return ResponseEntity.noContent().build();
  }

  public record Provision(
      @NotBlank @Size(max = 200) String identityId,
      @NotBlank @Size(max = 200) String username,
      @NotBlank @Size(min = 6, max = 1024) String password,
      @Size(max = 200) String tenantId,
      @Size(max = 320) String recoveryEmail) {}

  public record PasswordChange(
      @NotBlank String identityId,
      @NotBlank @Size(max = 1024) String currentPassword,
      @NotBlank @Size(min = 6, max = 1024) String newPassword) {}

  public record Recovery(@NotBlank @Size(max = 200) String username) {}

  public record Reset(
      @NotBlank @Size(max = 200) String token,
      @NotBlank @Size(min = 6, max = 1024) String newPassword) {}

  public record Revoke(@NotBlank @Size(max = 200) String identityId) {}
}
