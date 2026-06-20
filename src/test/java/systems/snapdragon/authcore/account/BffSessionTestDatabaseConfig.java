package systems.snapdragon.authcore.account;

import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.r2dbc.connection.init.ConnectionFactoryInitializer;
import org.springframework.r2dbc.connection.init.ResourceDatabasePopulator;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Self-contained R2DBC-H2 wiring for the {@link BffSessionRepository} data slice. auth-core is
 * a LIBRARY with no Liquibase changelog of its own (admin-bff owns the migrations), so the
 * {@code bff_session} schema is applied from {@code bff-session-schema.sql} by a reactive
 * {@link ConnectionFactoryInitializer} over the same H2 mem store the repository reads. H2 runs
 * in PostgreSQL-compat mode so the production partial-update SQL (incl. {@code now()}) exercises
 * here as on Postgres. Each test class gets a UNIQUE db name so classes don't share rows.
 */
@TestConfiguration(proxyBeanMethods = false)
public class BffSessionTestDatabaseConfig {

    private static final AtomicInteger DB_SEQ = new AtomicInteger();

    private final String dbName = "authcore_bffsession_" + DB_SEQ.incrementAndGet();

    private static final String H2_OPTS =
            ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;USER=sa;PASSWORD=";

    @Bean
    public ConnectionFactory connectionFactory() {
        return ConnectionFactories.get("r2dbc:h2:mem:///" + dbName + H2_OPTS);
    }

    /** Apply the bff_session DDL over the shared H2 store before any query runs. */
    @Bean
    public ConnectionFactoryInitializer schemaInitializer(ConnectionFactory connectionFactory) {
        ConnectionFactoryInitializer init = new ConnectionFactoryInitializer();
        init.setConnectionFactory(connectionFactory);
        init.setDatabasePopulator(new ResourceDatabasePopulator(
                new ClassPathResource("bff-session-schema.sql")));
        return init;
    }
}
