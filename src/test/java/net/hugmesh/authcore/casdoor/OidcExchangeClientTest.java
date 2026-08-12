package net.hugmesh.authcore.casdoor;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit coverage for the OIDC token client using a stubbed {@link ExchangeFunction} (no real
 * Casdoor): code-exchange + refresh response mapping, and the {@code error} body -> failure
 * mapping. Verifies the request is a form POST to the configured token path.
 */
class OidcExchangeClientTest {

    private static OidcExchangeClient clientReturning(String json, AtomicReference<ClientRequest> captured) {
        ExchangeFunction stub = request -> {
            captured.set(request);
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body(json)
                    .build());
        };
        WebClient wc = WebClient.builder().exchangeFunction(stub).build();
        return new OidcExchangeClient(wc, "/api/login/oauth/access_token", "user-bff", "secret", 3600L);
    }

    @Test
    void exchangeCodeMapsAllFields() {
        AtomicReference<ClientRequest> req = new AtomicReference<>();
        OidcExchangeClient client = clientReturning(
                "{\"access_token\":\"AT\",\"refresh_token\":\"RT\",\"id_token\":\"IT\",\"expires_in\":1200}", req);

        StepVerifier.create(client.exchangeCode("the-code", "the-verifier", "https://hugmesh.systems/login/callback"))
                .assertNext(t -> {
                    assertThat(t.accessToken()).isEqualTo("AT");
                    assertThat(t.refreshToken()).isEqualTo("RT");
                    assertThat(t.idToken()).isEqualTo("IT");
                    assertThat(t.expiresInSeconds()).isEqualTo(1200L);
                })
                .verifyComplete();

        assertThat(req.get().method().name()).isEqualTo("POST");
        assertThat(req.get().url().getPath()).isEqualTo("/api/login/oauth/access_token");
    }

    @Test
    void refreshMapsTokensAndFallsBackToDefaultExpiry() {
        AtomicReference<ClientRequest> req = new AtomicReference<>();
        OidcExchangeClient client = clientReturning(
                "{\"access_token\":\"AT2\",\"refresh_token\":\"RT2\"}", req);  // no expires_in

        StepVerifier.create(client.refresh("old-rt"))
                .assertNext(t -> {
                    assertThat(t.accessToken()).isEqualTo("AT2");
                    assertThat(t.refreshToken()).isEqualTo("RT2");
                    assertThat(t.idToken()).isNull();
                    assertThat(t.expiresInSeconds()).isEqualTo(3600L);   // configured default
                })
                .verifyComplete();
    }

    @Test
    void errorBodyMapsToFailure() {
        AtomicReference<ClientRequest> req = new AtomicReference<>();
        OidcExchangeClient client = clientReturning("{\"error\":\"invalid_grant\"}", req);

        StepVerifier.create(client.refresh("revoked-rt"))
                .expectErrorMatches(e -> e instanceof IllegalStateException
                        && e.getMessage().contains("invalid_grant"))
                .verify();
    }
}
