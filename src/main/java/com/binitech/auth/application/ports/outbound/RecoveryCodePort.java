package com.binitech.auth.application.ports.outbound;

import java.util.List;
import java.util.Optional;

public interface RecoveryCodePort {
  List<String> generate();

  Optional<String> digest(String code);
}
