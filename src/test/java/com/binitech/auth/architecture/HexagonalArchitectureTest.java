package com.binitech.auth.architecture;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HexagonalArchitectureTest {
  @TempDir Path compiled;

  @Test
  void coreCompilesWithoutFrameworksAndDependenciesPointInward() throws Exception {
    compile("domain");
    compile("application");
  }

  private void compile(String layer) throws Exception {
    var compiler = ToolProvider.getSystemJavaCompiler();
    assertNotNull(compiler, "Use JDK 21 to check architecture");
    var args =
        new ArrayList<>(
            List.of(
                "--release",
                "21",
                "-encoding",
                "UTF-8",
                "-classpath",
                compiled.toString(),
                "-sourcepath",
                compiled.toString(),
                "-d",
                compiled.toString()));
    try (var sources = Files.walk(Path.of("src/main/java/com/binitech/auth", layer))) {
      args.addAll(sources.filter(p -> p.toString().endsWith(".java")).map(Path::toString).toList());
    }
    assertEquals(
        0,
        compiler.run(null, null, null, args.toArray(String[]::new)),
        layer + " must not depend on adapters, Spring, persistence or JWT libraries");
  }
}
