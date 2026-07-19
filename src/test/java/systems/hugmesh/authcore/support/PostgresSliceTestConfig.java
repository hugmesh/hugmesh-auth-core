package systems.hugmesh.authcore.support;

import io.r2dbc.spi.ConnectionFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.r2dbc.connection.init.ConnectionFactoryInitializer;
import org.springframework.r2dbc.connection.init.ResourceDatabasePopulator;

/**
 * Applies the MFA test DDL ({@code mfa-schema.sql}) over the Testcontainers-Postgres database
 * that {@link systems.hugmesh.commons.testsupport.PostgresTestSupport} provisions, for the
 * {@code @DataR2dbcTest} MFA-repository SLICES.
 *
 * <p>WHY a dedicated config (and why NOT Liquibase): auth-core is a LIBRARY with NO Liquibase
 * changelog of its own — the production MFA DDL lives in admin-bff changesets 151/152. So,
 * unlike the mod-bff exemplar (which runs its own production changelog via a
 * {@code SpringLiquibase} bean), this slice applies a hand-mirrored {@code mfa-schema.sql}
 * reactively, the same {@link ConnectionFactoryInitializer} idiom the existing
 * {@code BffSessionTestDatabaseConfig} uses — except pointed at the REAL Postgres container
 * the {@code PostgresTestSupport} {@code @DynamicPropertySource} published into
 * {@code spring.r2dbc.*}, NOT H2.
 *
 * <p>WHY Postgres and not H2: the release-2.3.0 DB-generated-UUID-PK migration relies on a
 * {@code (gen_random_uuid())::text} column DEFAULT and {@code INSERT ... RETURNING id};
 * NEITHER works on the H2 PostgreSQL-compat store the other auth-core slices use. The
 * {@code @DataR2dbcTest} slice auto-wires the reactive {@link ConnectionFactory} from
 * {@code spring.r2dbc.*}, so this initializer runs the schema over the same container db the
 * repository then queries.
 */
@TestConfiguration(proxyBeanMethods = false)
public class PostgresSliceTestConfig {

    /** Apply the MFA DDL over the container db before any repository query runs. The slice's
     *  reactive {@link ConnectionFactory} (wired from {@code spring.r2dbc.*}) is injected, so
     *  the schema lands in exactly the db the repository reads. */
    @Bean
    public ConnectionFactoryInitializer mfaSchemaInitializer(ConnectionFactory connectionFactory) {
        ConnectionFactoryInitializer init = new ConnectionFactoryInitializer();
        init.setConnectionFactory(connectionFactory);
        init.setDatabasePopulator(new ResourceDatabasePopulator(
                new ClassPathResource("mfa-schema.sql")));
        return init;
    }
}
