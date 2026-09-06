package com.binitech.auth.application.ports.outbound;

import com.binitech.auth.domain.Identity;
import java.util.List;
import java.util.Optional;

public interface IdentityRepositoryPort {
  List<Identity> findCandidates(String username, String tenantId);

  Optional<Identity> findById(String id);
}
