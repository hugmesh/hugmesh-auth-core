package systems.snapdragon.authcore;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

/**
 * Minimal {@code @SpringBootConfiguration} anchor for the auth-core {@code @DataR2dbcTest}
 * MFA-repository slices. auth-core is a LIBRARY (no {@code @SpringBootApplication}), so a
 * slice test has nothing to search upwards for; this empty config gives the test context a
 * root and enables auto-config so {@code @DataR2dbcTest} brings up the R2DBC repository
 * infrastructure over the {@code PostgresSliceTestConfig} Testcontainers-Postgres store.
 *
 * <p>Anchored at the {@code systems.snapdragon.authcore} ROOT package (not {@code .support})
 * ON PURPOSE: {@code @DataR2dbcTest}'s {@code @EnableR2dbcRepositories} scans from THIS class's
 * package, so the root package lets it discover the {@code mfa.*} R2DBC repositories the slices
 * autowire (a config in {@code .support} would scan only that leaf and find no repositories).
 */
@SpringBootConfiguration
@EnableAutoConfiguration
public class SliceTestApp {
}
