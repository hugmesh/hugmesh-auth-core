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
 * R2DBC-H2 wiring for {@link SsoFlowTest}: ONE database carrying the three tables the login
 * path touches ({@code account}, {@code allowlist}, {@code bff_session}), so the real
 * repositories and the real {@link AccountStore} facade run over the same store the way they
 * do in a consumer. H2 runs in PostgreSQL-compat mode, as in the other slices.
 */
@TestConfiguration(proxyBeanMethods = false)
public class SsoFlowTestDatabaseConfig {

    private static final AtomicInteger DB_SEQ = new AtomicInteger();

    private final String dbName = "authcore_ssoflow_" + DB_SEQ.incrementAndGet();

    private static final String H2_OPTS =
            ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;USER=sa;PASSWORD=";

    @Bean
    public ConnectionFactory connectionFactory() {
        return ConnectionFactories.get("r2dbc:h2:mem:///" + dbName + H2_OPTS);
    }

    @Bean
    public ConnectionFactoryInitializer schemaInitializer(ConnectionFactory connectionFactory) {
        ConnectionFactoryInitializer init = new ConnectionFactoryInitializer();
        init.setConnectionFactory(connectionFactory);
        init.setDatabasePopulator(new ResourceDatabasePopulator(
                new ClassPathResource("account-schema.sql"),
                new ClassPathResource("allowlist-schema.sql"),
                new ClassPathResource("bff-session-schema.sql")));
        return init;
    }
}
