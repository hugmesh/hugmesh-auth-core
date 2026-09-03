package net.hugmesh.authcore.account;

import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.r2dbc.connection.init.ConnectionFactoryInitializer;
import org.springframework.r2dbc.connection.init.ResourceDatabasePopulator;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Self-contained R2DBC-H2 wiring for the {@link AllowlistRepository} data slice — the same
 * idiom as {@link BffSessionTestDatabaseConfig}: auth-core is a LIBRARY with no Liquibase
 * changelog of its own, so the {@code allowlist} schema (changesets 003 + 220) is applied
 * from {@code allowlist-schema.sql} by a reactive {@link ConnectionFactoryInitializer} over
 * the same H2 mem store the repository reads. H2 runs in PostgreSQL-compat mode so the
 * derived-finder SQL exercises here as on Postgres.
 *
 * <p>{@code DB_SEQ} increments once per config-bean INSTANCE, i.e. per APPLICATION CONTEXT —
 * not per test class. Two test classes with identical context configuration share one cached
 * context and therefore ONE database; give a class its own context-cache key (a
 * {@code @TestPropertySource} marker, as {@code AccountStoreAllowlistGateTest} does) when it
 * needs an isolated one.
 */
@TestConfiguration(proxyBeanMethods = false)
public class AllowlistTestDatabaseConfig {

    private static final AtomicInteger DB_SEQ = new AtomicInteger();

    private final String dbName = "authcore_allowlist_" + DB_SEQ.incrementAndGet();

    private static final String H2_OPTS =
            ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;USER=sa;PASSWORD=";

    @Bean
    public ConnectionFactory connectionFactory() {
        return ConnectionFactories.get("r2dbc:h2:mem:///" + dbName + H2_OPTS);
    }

    /** Apply the allowlist DDL over the shared H2 store before any query runs. */
    @Bean
    public ConnectionFactoryInitializer schemaInitializer(ConnectionFactory connectionFactory) {
        ConnectionFactoryInitializer init = new ConnectionFactoryInitializer();
        init.setConnectionFactory(connectionFactory);
        init.setDatabasePopulator(new ResourceDatabasePopulator(
                new ClassPathResource("allowlist-schema.sql")));
        return init;
    }
}
