package net.hugmesh.authcore.username;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManagerFactory;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mTLS <b>applied</b> path of {@link FederationUsernameConfig}, end to end over real sockets —
 * the one leg the unit tests cannot reach, because it needs a PKCS12 identity on disk and a peer
 * that actually demands a client certificate.
 *
 * <p>The in-cluster topology this reproduces (see the generator's {@code admin-bff-api/deployment.yaml}
 * and {@code federation-api/deployment.yaml}): the Casdoor token endpoint is <b>plain http</b>
 * while federation-api is <b>https with {@code client-auth=need}</b>, and this config routes BOTH
 * hops through ONE reactor-netty connector that carries the service's client certificate. Two
 * things must therefore hold at once, and neither is provable by inspection:
 * <ol>
 *   <li>a connector with an SSL provider configured still speaks plain http to an {@code http://}
 *       base (the premise {@code OidcExchangeClientSsl}'s Javadoc asserts) — otherwise enabling
 *       the gate would break every mint and fail every check closed;</li>
 *   <li>the https hop presents OUR certificate and is accepted by a {@code REQUIRE} peer, and the
 *       minted bearer rides on it.</li>
 * </ol>
 *
 * <p>A self-signed certificate is generated at test time with BouncyCastle (already a compile
 * dependency) and used as the server identity, the trust anchor and the client identity at once;
 * the stores live in a JUnit temp dir. The negative control runs the identical stores and peer with
 * the gate OFF: the config then hands out Boot's plain connector, which carries neither our client
 * certificate nor a trust anchor for the self-signed peer, so OUR side aborts the handshake on the
 * server certificate (client-side PKIX path building fails — {@code certificate_unknown} in the run
 * log) before a client certificate or the bearer is ever sent; nothing reaches the handler and the
 * check fails CLOSED. The peer's {@code REQUIRE} would refuse a certificate-less client too, but the
 * handshake never gets that far — client-certificate presentation is pinned by the positive case's
 * {@code PEER_SUBJECT} assertion, not by this control. Either way the gate is load-bearing rather
 * than decorative.
 */
class FederationUsernameMtlsWireTest {

    /** The consumer-side bean the config expects from Boot's WebClient auto-configuration. */
    @Configuration(proxyBeanMethods = false)
    static class Support {
        @Bean
        WebClient.Builder webClientBuilder() {
            return WebClient.builder();
        }
    }

    private static final char[] PW = "changeit".toCharArray();
    private static final String CN = "hugmesh-auth-core-wire-test";
    private static final String CASDOOR_TOKEN_PATH = "/api/login/oauth/access_token";
    private static final Duration WIRE_TIMEOUT = Duration.ofSeconds(15);

    @TempDir
    static Path stores;
    private static Path keyStore;
    private static Path trustStore;

    private static DisposableServer federation;
    private static DisposableServer casdoor;

    // What the two stubs observed.
    private static final AtomicInteger MINTS = new AtomicInteger();
    private static final AtomicReference<String> MINT_FORM = new AtomicReference<>();
    private static final AtomicInteger FEDERATION_CALLS = new AtomicInteger();
    private static final AtomicReference<String> AUTHORIZATION = new AtomicReference<>();
    private static final AtomicReference<String> PEER_SUBJECT = new AtomicReference<>();

    @BeforeAll
    static void startPeers() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X509Certificate cert = selfSigned(kp);

        keyStore = stores.resolve("keystore.p12");
        trustStore = stores.resolve("truststore.p12");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("svc", kp.getPrivate(), PW, new Certificate[] {cert});
        try (OutputStream out = Files.newOutputStream(keyStore)) {
            ks.store(out, PW);
        }
        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("cluster-ca", cert);
        try (OutputStream out = Files.newOutputStream(trustStore)) {
            ts.store(out, PW);
        }

        // federation-api stand-in: https, and the client MUST present a certificate we trust.
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, PW);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        SslContext serverSsl = SslContextBuilder.forServer(kmf)
                .trustManager(tmf)
                .clientAuth(ClientAuth.REQUIRE)
                .build();
        federation = HttpServer.create().host("127.0.0.1").port(0)
                .secure(spec -> spec.sslContext(serverSsl))
                .route(r -> r.get("/api/federation/username/{candidate}/availability", (req, res) -> {
                    FEDERATION_CALLS.incrementAndGet();
                    AUTHORIZATION.set(req.requestHeaders().get(HttpHeaderNames.AUTHORIZATION));
                    req.withConnection(conn -> {
                        SslHandler ssl = conn.channel().pipeline().get(SslHandler.class);
                        if (ssl != null) {
                            try {
                                Certificate[] peer = ssl.engine().getSession().getPeerCertificates();
                                PEER_SUBJECT.set(((X509Certificate) peer[0]).getSubjectX500Principal().getName());
                            } catch (SSLPeerUnverifiedException e) {
                                PEER_SUBJECT.set("(no peer certificate)");
                            }
                        }
                    });
                    return res.header(HttpHeaderNames.CONTENT_TYPE, "application/json")
                            .sendString(Mono.just("{\"available\":true}"));
                }))
                .bindNow();

        // Casdoor stand-in: PLAIN http, exactly like casdoor.hugmesh-pki.svc.cluster.local:8000.
        casdoor = HttpServer.create().host("127.0.0.1").port(0)
                .route(r -> r.post(CASDOOR_TOKEN_PATH, (req, res) ->
                        req.receive().aggregate().asString().defaultIfEmpty("").flatMap(form -> {
                            MINTS.incrementAndGet();
                            MINT_FORM.set(form);
                            return res.header(HttpHeaderNames.CONTENT_TYPE, "application/json")
                                    .sendString(Mono.just("{\"access_token\":\"svc-jwt\",\"expires_in\":3600}"))
                                    .then();
                        })))
                .bindNow();
    }

    @AfterAll
    static void stopPeers() {
        if (federation != null) {
            federation.disposeNow();
        }
        if (casdoor != null) {
            casdoor.disposeNow();
        }
    }

    @BeforeEach
    void reset() {
        MINTS.set(0);
        MINT_FORM.set(null);
        FEDERATION_CALLS.set(0);
        AUTHORIZATION.set(null);
        PEER_SUBJECT.set(null);
    }

    /** A self-signed cert good for server AND client auth, with the SANs hostname verification needs. */
    private static X509Certificate selfSigned(KeyPair kp) throws Exception {
        X500Name name = new X500Name("CN=" + CN + ",O=hugmesh");
        Instant now = Instant.now();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minusSeconds(300)), Date.from(now.plusSeconds(3600)),
                name, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(
                new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
        b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[] {
                new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
                new GeneralName(GeneralName.dNSName, "localhost")}));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(b.build(signer));
    }

    /** The real config, gate ON, pointed at the two live stubs, with the outbound-mTLS gate as given. */
    private static ApplicationContextRunner runner(boolean mtlsEnabled) {
        return new ApplicationContextRunner()
                .withUserConfiguration(Support.class, FederationUsernameConfig.class)
                .withPropertyValues(
                        "federation.username-gate.enabled=true",
                        "federation.username-gate.base-url=https://127.0.0.1:" + federation.port(),
                        "app.casdoor.platform.base-url=http://127.0.0.1:" + casdoor.port(),
                        "app.casdoor.platform.client-id=app-admin-bff",
                        "app.casdoor.platform.client-secret=s3cret",
                        "hugmesh.mtls.client.enabled=" + mtlsEnabled,
                        "hugmesh.mtls.client.key-store=" + keyStore,
                        "hugmesh.mtls.client.key-store-password=changeit",
                        "hugmesh.mtls.client.trust-store=" + trustStore,
                        "hugmesh.mtls.client.trust-store-password=changeit");
    }

    @Test
    @DisplayName("mTLS gate ON + stores present: the mint stays PLAIN http, then the https hop presents "
            + "our client certificate and carries the minted bearer — the real answer comes back")
    void mtlsOn_mintsPlain_thenPresentsClientCertAndBearer() {
        runner(true).run(ctx -> {
            assertThat(ctx).hasNotFailed();
            FederationUsernameClient c = ctx.getBean(FederationUsernameClient.class);
            assertThat(c.enabled()).isTrue();
            assertThat(c.serviceBearerConfigured()).isTrue();

            UsernameAvailability av = c.availability("alice").block(WIRE_TIMEOUT);

            assertThat(av).isNotNull();
            assertThat(av.available())
                    .as("federation's real answer, not a fail-closed collision: %s", av.reason())
                    .isTrue();
            // (1) The mint went over PLAIN http through the SAME SSL-configured connector.
            assertThat(MINTS.get()).isEqualTo(1);
            assertThat(MINT_FORM.get())
                    .contains("grant_type=client_credentials")
                    .contains("client_id=app-admin-bff")
                    .contains("client_secret=s3cret");
            // (2) The client-auth=need peer saw OUR certificate, and the bearer rode on that hop.
            assertThat(FEDERATION_CALLS.get()).isEqualTo(1);
            assertThat(AUTHORIZATION.get()).isEqualTo("Bearer svc-jwt");
            assertThat(PEER_SUBJECT.get()).contains("CN=" + CN);
        });
    }

    @Test
    @DisplayName("gate OFF against the SAME https peer: the plain connector trusts no self-signed cert, so "
            + "OUR side aborts the handshake (client-side PKIX) before any credential is sent, and the check "
            + "fails CLOSED")
    void mtlsOff_sameStoresAndPeer_failsClosed() {
        runner(false).run(ctx -> {
            assertThat(ctx).hasNotFailed();
            FederationUsernameClient c = ctx.getBean(FederationUsernameClient.class);

            UsernameAvailability av = c.availability("alice").block(WIRE_TIMEOUT);

            assertThat(av).isNotNull();
            assertThat(av.available()).isFalse();
            assertThat(av.reason()).isEqualTo("federation-unavailable");
            // The mint itself still succeeded (plain http needs no gate) — it is the TLS hop that fails, on
            // OUR side: no trust anchor for the peer's self-signed certificate, so no client certificate or
            // bearer was ever offered for the peer's REQUIRE to judge.
            assertThat(MINTS.get()).isEqualTo(1);
            assertThat(FEDERATION_CALLS.get()).as("no request ever reached the handler").isZero();
        });
    }
}
