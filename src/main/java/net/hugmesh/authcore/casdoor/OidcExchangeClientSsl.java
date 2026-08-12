package net.hugmesh.authcore.casdoor;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

/**
 * OUTBOUND (client-side) mTLS for the reactive {@link org.springframework.web.reactive.function.client.WebClient}
 * that {@link OidcExchangeClient} uses to reach Casdoor's token endpoint (the server-side
 * PKCE code→token exchange + refresh legs). This is the leg that carries the OIDC
 * {@code code}/{@code client_secret}/tokens to Casdoor, so on a non-mesh deployment it should
 * ride an encrypted, mutually-authenticated channel rather than plaintext HTTP.
 *
 * <p>Deliberately mirrors the user-bff {@code FederationHttpClientSsl} — SAME gate + SAME
 * {@code SSL_*}/{@code hugmesh.mtls.client.*} property names — so ONE set of PKCS12 stores +
 * one flag configures outbound mTLS across every internal Java hop (federation, admin-bff
 * internal, Casdoor exchange). Living in auth-core lets every BFF that redeems tokens
 * (user-bff callback path, admin-bff exchange endpoint) inherit it.
 *
 * <p>GATED, DEFAULT OFF: {@code hugmesh.mtls.client.enabled=false}. Local/dev/CI (plain
 * http, no stores mounted) is unaffected — the WebClient keeps its default connector. It also
 * only negotiates TLS when the exchange base URL ({@code app.bff.oidc.issuer}) is
 * {@code https://}; a plain-http in-mesh base stays plain even with the gate on.
 */
@ConfigurationProperties(prefix = "hugmesh.mtls.client")
public class OidcExchangeClientSsl {

    private static final Logger log = LoggerFactory.getLogger(OidcExchangeClientSsl.class);

    /** Master gate — when false, no SSL is applied and the default connector is kept. */
    private boolean enabled = false;
    /** PKCS12 keystore holding THIS service's PKI client identity (cert + key). */
    private String keyStore = "/stores/keystore.p12";
    private String keyStorePassword = "";
    private String keyStoreType = "PKCS12";
    /** PKCS12 truststore holding the cluster CA (to trust the target's server cert). */
    private String trustStore = "/stores/truststore.p12";
    private String trustStorePassword = "";
    private String trustStoreType = "PKCS12";

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getKeyStore() { return keyStore; }
    public void setKeyStore(String keyStore) { this.keyStore = keyStore; }
    public String getKeyStorePassword() { return keyStorePassword; }
    public void setKeyStorePassword(String keyStorePassword) { this.keyStorePassword = keyStorePassword; }
    public String getKeyStoreType() { return keyStoreType; }
    public void setKeyStoreType(String keyStoreType) { this.keyStoreType = keyStoreType; }
    public String getTrustStore() { return trustStore; }
    public void setTrustStore(String trustStore) { this.trustStore = trustStore; }
    public String getTrustStorePassword() { return trustStorePassword; }
    public void setTrustStorePassword(String trustStorePassword) { this.trustStorePassword = trustStorePassword; }
    public String getTrustStoreType() { return trustStoreType; }
    public void setTrustStoreType(String trustStoreType) { this.trustStoreType = trustStoreType; }

    /**
     * Whether outbound client-presentation mTLS should be applied. True only when the gate is
     * on AND the identity keystore file is actually present (so a misconfigured pod degrades to
     * plain http rather than crashing on boot, and local/test never touches the filesystem).
     */
    public boolean shouldApply() {
        if (!enabled) {
            return false;
        }
        boolean present = keyStore != null && Files.exists(Path.of(keyStore));
        if (!present) {
            log.warn("[oidc-exchange-mtls] enabled but key-store '{}' is absent — outbound mTLS NOT applied", keyStore);
        }
        return present;
    }

    /**
     * Decorate a reactor-netty {@link HttpClient} with the client-identity keystore + cluster-CA
     * truststore when {@link #shouldApply()}; otherwise return it unchanged.
     */
    public HttpClient customize(HttpClient httpClient) {
        if (!shouldApply()) {
            return httpClient;
        }
        try {
            SslContext ssl = buildSslContext();
            log.info("[oidc-exchange-mtls] outbound client-cert presentation ENABLED (key-store={}, trust-store={})",
                    keyStore, trustStore);
            return httpClient.secure(spec -> spec.sslContext(ssl));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build outbound mTLS SslContext from "
                    + keyStore + " / " + trustStore, e);
        }
    }

    SslContext buildSslContext() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(load(keyStore, keyStoreType, keyStorePassword), pw(keyStorePassword));

        SslContextBuilder builder = SslContextBuilder.forClient().keyManager(kmf);
        if (trustStore != null && Files.exists(Path.of(trustStore))) {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(load(trustStore, trustStoreType, trustStorePassword));
            builder.trustManager(tmf);
        }
        return builder.build();
    }

    private static KeyStore load(String path, String type, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance(type == null ? "PKCS12" : type);
        try (InputStream in = Files.newInputStream(Path.of(path))) {
            ks.load(in, pw(password));
        }
        return ks;
    }

    private static char[] pw(String password) {
        return password == null ? new char[0] : password.toCharArray();
    }
}
