package net.hugmesh.authcore.username;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.authcore.casdoor.CasdoorServiceTokenClient;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link FederationUsernameConfig} against a REAL Spring context: the bean is always present
 * and default-OFF; the ROLE_SERVICE bearer is wired from the dedicated
 * {@code federation.username-gate.service-bearer.*} keys OR the platform-wide
 * {@code app.casdoor.platform.*} fallback (dedicated wins); a partial credential set wires no
 * bearer; and an ENABLED gate with no bearer WARNs loudly at boot (a real log assertion, not a
 * claim) because against federation-api it fails every check closed.
 */
class FederationUsernameConfigTest {

    /** The consumer-side bean the config expects from Boot's WebClient auto-configuration. */
    @Configuration(proxyBeanMethods = false)
    static class Support {
        @Bean
        WebClient.Builder webClientBuilder() {
            return WebClient.builder();
        }
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(Support.class, FederationUsernameConfig.class);

    private ListAppender<ILoggingEvent> logs;
    private ch.qos.logback.classic.Logger configLogger;

    @BeforeEach
    void attachLogAppender() {
        LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
        configLogger = ctx.getLogger(FederationUsernameConfig.class);
        logs = new ListAppender<>();
        logs.setContext(ctx);
        logs.start();
        configLogger.addAppender(logs);
    }

    @AfterEach
    void detachLogAppender() {
        configLogger.detachAppender(logs);
        logs.stop();
    }

    private List<ILoggingEvent> warnings() {
        return logs.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
    }

    private static CasdoorServiceTokenClient bearerOf(FederationUsernameClient c) {
        return (CasdoorServiceTokenClient) c.serviceBearer();
    }

    @Test
    @DisplayName("defaults: bean present, gate OFF, no bearer, nothing logged")
    void defaults_beanPresent_disabled_noBearer() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(FederationUsernameClient.class);
            FederationUsernameClient c = ctx.getBean(FederationUsernameClient.class);
            assertThat(c.enabled()).isFalse();
            assertThat(c.serviceBearerConfigured()).isFalse();
            assertThat(warnings()).isEmpty();
        });
    }

    @Test
    @DisplayName("app.casdoor.platform.* alone wires the bearer — a consumer that already carries them needs nothing new")
    void platformCredentials_wireTheBearer() {
        runner.withPropertyValues(
                        "app.casdoor.platform.base-url=http://casdoor.hugmesh-pki.svc.cluster.local:8000",
                        "app.casdoor.platform.client-id=app-admin-bff",
                        "app.casdoor.platform.client-secret=s3cret")
                .run(ctx -> {
                    FederationUsernameClient c = ctx.getBean(FederationUsernameClient.class);
                    assertThat(c.serviceBearerConfigured()).isTrue();
                    assertThat(bearerOf(c).clientId()).isEqualTo("app-admin-bff");
                });
    }

    @Test
    @DisplayName("dedicated federation.username-gate.service-bearer.* keys alone wire the bearer")
    void dedicatedCredentials_wireTheBearer() {
        runner.withPropertyValues(
                        "federation.username-gate.service-bearer.casdoor-base-url=http://casdoor:8000",
                        "federation.username-gate.service-bearer.client-id=gate-only-client",
                        "federation.username-gate.service-bearer.client-secret=s3cret")
                .run(ctx -> {
                    FederationUsernameClient c = ctx.getBean(FederationUsernameClient.class);
                    assertThat(c.serviceBearerConfigured()).isTrue();
                    assertThat(bearerOf(c).clientId()).isEqualTo("gate-only-client");
                });
    }

    @Test
    @DisplayName("when both are set the dedicated key wins over the platform fallback")
    void dedicatedKeys_overridePlatformFallback() {
        runner.withPropertyValues(
                        "app.casdoor.platform.base-url=http://casdoor:8000",
                        "app.casdoor.platform.client-id=platform-client",
                        "app.casdoor.platform.client-secret=platform-secret",
                        "federation.username-gate.service-bearer.client-id=gate-only-client")
                .run(ctx -> assertThat(bearerOf(ctx.getBean(FederationUsernameClient.class)).clientId())
                        .isEqualTo("gate-only-client"));
    }

    @Test
    @DisplayName("a partial credential set (secret missing) wires NO bearer rather than a broken one")
    void partialCredentials_wireNoBearer() {
        runner.withPropertyValues(
                        "app.casdoor.platform.base-url=http://casdoor:8000",
                        "app.casdoor.platform.client-id=app-admin-bff")
                .run(ctx -> assertThat(ctx.getBean(FederationUsernameClient.class).serviceBearerConfigured())
                        .isFalse());
    }

    @Test
    @DisplayName("THE TRAP: gate ON with no bearer boots (never a crash-loop) but WARNs that every check fails closed")
    void enabled_withoutBearer_bootsAndWarnsLoudly() {
        runner.withPropertyValues("federation.username-gate.enabled=true")
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    FederationUsernameClient c = ctx.getBean(FederationUsernameClient.class);
                    assertThat(c.enabled()).isTrue();
                    assertThat(c.serviceBearerConfigured()).isFalse();
                    assertThat(warnings()).hasSize(1);
                    String msg = warnings().get(0).getFormattedMessage();
                    assertThat(msg).contains("ENABLED but NO service-bearer credentials");
                    assertThat(msg).contains("fail CLOSED");
                    assertThat(msg).contains("client-secret set=false");
                });
    }

    @Test
    @DisplayName("gate ON with a full credential set: enabled, bearer wired, no WARN")
    void enabled_withBearer_noWarn() {
        runner.withPropertyValues(
                        "federation.username-gate.enabled=true",
                        "app.casdoor.platform.base-url=http://casdoor:8000",
                        "app.casdoor.platform.client-id=app-admin-bff",
                        "app.casdoor.platform.client-secret=s3cret")
                .run(ctx -> {
                    FederationUsernameClient c = ctx.getBean(FederationUsernameClient.class);
                    assertThat(c.enabled()).isTrue();
                    assertThat(c.serviceBearerConfigured()).isTrue();
                    assertThat(warnings()).isEmpty();
                });
    }

    @Test
    @DisplayName("the WARN never echoes the secret value")
    void warn_neverEchoesSecret() {
        runner.withPropertyValues(
                        "federation.username-gate.enabled=true",
                        "app.casdoor.platform.client-secret=super-secret-value")
                .run(ctx -> {
                    assertThat(warnings()).hasSize(1);
                    assertThat(warnings().get(0).getFormattedMessage())
                            .doesNotContain("super-secret-value")
                            .contains("client-secret set=true");
                });
    }

    @Test
    @DisplayName("outbound mTLS gate ON but stores absent degrades to plain — the context still refreshes")
    void mtlsGateOn_storesAbsent_degradesToPlain() {
        runner.withPropertyValues(
                        "hugmesh.mtls.client.enabled=true",
                        "hugmesh.mtls.client.key-store=/nonexistent/keystore.p12")
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).hasSingleBean(FederationUsernameClient.class);
                });
    }
}
