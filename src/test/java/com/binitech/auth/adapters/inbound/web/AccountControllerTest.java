package com.binitech.auth.adapters.inbound.web;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.binitech.auth.application.ports.inbound.AccountLifecycle;
import com.binitech.auth.config.SecurityConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(
    controllers = AccountController.class,
    properties = {
      "auth.service-key=test-machine-key-with-at-least-32-bytes",
      "cors.allowed-origins=https://pdv.example"
    })
@Import(SecurityConfiguration.class)
class AccountControllerTest {
  @Autowired MockMvc mvc;
  @MockitoBean AccountLifecycle accounts;

  @Test
  void rejectsMissingMachineCredential() throws Exception {
    mvc.perform(
            post("/api/internal/identities/revoke")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"identityId\":\"u1\"}"))
        .andExpect(status().isUnauthorized());
    verifyNoInteractions(accounts);
  }

  @Test
  void endUserBearerDoesNotGrantAdministration() throws Exception {
    mvc.perform(
            post("/api/internal/identities/revoke")
                .header("Authorization", "Bearer end-user-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"identityId\":\"u1\"}"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void authenticatesConfiguredMachineCredential() throws Exception {
    mvc.perform(
            post("/api/internal/identities/revoke")
                .header("X-Auth-Service-Key", "test-machine-key-with-at-least-32-bytes")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"identityId\":\"u1\"}"))
        .andExpect(status().isNoContent());
    verify(accounts).revokeSessions("u1");
  }
}
