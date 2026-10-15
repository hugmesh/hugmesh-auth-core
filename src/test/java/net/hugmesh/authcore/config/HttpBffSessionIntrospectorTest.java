package net.hugmesh.authcore.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** {@link HttpBffSessionIntrospector} against a canned {@code ExchangeFunction}, no network. */
class HttpBffSessionIntrospectorTest {

    private static HttpBffSessionIntrospector over(HttpStatus status, String body,
                                                   AtomicReference<ClientRequest> seen) {
        WebClient client = WebClient.builder()
                .baseUrl("http://admin-bff.internal")
                .exchangeFunction(req -> {
                    seen.set(req);
                    return Mono.just(ClientResponse.create(status)
                            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                            .body(body)
                            .build());
                })
                .build();
        return new HttpBffSessionIntrospector(client);
    }

    @Test
    void sendsTheTokenAsBearerToTheIntrospectPath_andMapsTheBody() {
        var seen = new AtomicReference<ClientRequest>();
        var http = over(HttpStatus.OK, """
                {"id":"google:u@example.com","provider":"google","roles":["user","admin"],
                 "registrationComplete":true,"status":"active","mfaSatisfied":true,
                 "casdoorSub":"abc","issuer":"https://id.example"}""", seen);

        StepVerifier.create(http.introspect("bff_tok"))
                .assertNext(i -> {
                    assertThat(i.id()).isEqualTo("google:u@example.com");
                    assertThat(i.roles()).containsExactly("user", "admin");
                    assertThat(i.registrationComplete()).isTrue();
                    assertThat(i.mfaSatisfied()).isTrue();
                })
                .verifyComplete();

        assertThat(seen.get().method()).isEqualTo(HttpMethod.GET);
        assertThat(seen.get().url().getPath()).isEqualTo("/bff/internal/session/introspect");
        assertThat(seen.get().headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer bff_tok");
    }

    @Test
    void a401IsAnUnknownSession_notAnError() {
        var http = over(HttpStatus.UNAUTHORIZED, "{}", new AtomicReference<>());

        StepVerifier.create(http.introspect("bff_gone")).verifyComplete();
    }

    @Test
    void aServerErrorStaysAnError() {
        var http = over(HttpStatus.INTERNAL_SERVER_ERROR, "{}", new AtomicReference<>());

        StepVerifier.create(http.introspect("bff_tok"))
                .expectError(WebClientResponseException.InternalServerError.class)
                .verify();
    }

    @Test
    void omittedStatusIsNotDefaultedToActive() {
        var http = over(HttpStatus.OK,
                "{\"id\":\"x\",\"roles\":null,\"registrationComplete\":true,\"mfaSatisfied\":false}",
                new AtomicReference<>());

        StepVerifier.create(http.introspect("bff_tok"))
                .assertNext(i -> {
                    assertThat(i.status()).isNotEqualToIgnoringCase("active");
                    assertThat(i.roles()).isEmpty();
                })
                .verifyComplete();
    }

    @Test
    void explicitlyNullStatusIsNotDefaultedToActive() {
        var http = over(HttpStatus.OK,
                "{\"id\":\"x\",\"status\":null,\"registrationComplete\":true,\"mfaSatisfied\":false}",
                new AtomicReference<>());

        StepVerifier.create(http.introspect("bff_tok"))
                .assertNext(i -> assertThat(i.status()).isNotEqualToIgnoringCase("active"))
                .verifyComplete();
    }
}
