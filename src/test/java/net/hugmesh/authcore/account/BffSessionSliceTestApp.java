package net.hugmesh.authcore.account;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

/**
 * Minimal {@code @SpringBootConfiguration} anchor for the {@link BffSessionRepository}
 * {@code @DataR2dbcTest} slice. auth-core is a LIBRARY (no {@code @SpringBootApplication}), so
 * the slice test has nothing to search upwards for; this empty config gives the test context a
 * root. Auto-config is enabled so {@code @DataR2dbcTest} brings up the R2DBC repository
 * infrastructure over the {@link BffSessionTestDatabaseConfig} H2 store.
 */
@SpringBootConfiguration
@EnableAutoConfiguration
class BffSessionSliceTestApp {
}
