package net.hugmesh.authcore.mfa;

import com.webauthn4j.data.client.Origin;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** hugmesh-auth-core#39: the Relying Party chosen per request, and the fixed mode kept. */
class WebAuthnRelyingPartyTest {

    private static WebAuthnRelyingParty perRequest(String rpDomains, String issuer) {
        return new WebAuthnRelyingParty("", "", rpDomains, issuer);
    }

    @Test
    void fixedMode_whenRpIdIsSet_isThePre39Behaviour_forEveryRequest() {
        WebAuthnRelyingParty rp = new WebAuthnRelyingParty("admin.example.org",
                "https://admin.example.org", "", "https://id.example.org");
        assertThat(rp.isFixed()).isTrue();
        for (String origin : new String[]{null, "https://evil.test", "https://1.2.3.4"}) {
            WebAuthnRelyingParty.Rp r = rp.resolve(origin);
            assertThat(r.rpId()).isEqualTo("admin.example.org");
            assertThat(r.origins()).containsExactly(new Origin("https://admin.example.org"));
        }
    }

    @Test
    void fixedMode_withNoOrigins_keepsTheHttpsLocalhostDefault() {
        WebAuthnRelyingParty rp = new WebAuthnRelyingParty("localhost", "", "", "");
        assertThat(rp.resolve(null).origins()).containsExactly(new Origin("https://localhost"));
    }

    @Test
    void perRequest_theIssuerHost_isAMeshDomain() {
        WebAuthnRelyingParty rp = perRequest("", "https://mesh.example.org");
        assertThat(rp.isFixed()).isFalse();
        assertThat(rp.domains()).containsExactly("mesh.example.org");
        WebAuthnRelyingParty.Rp r = rp.resolve("https://mesh.example.org");
        assertThat(r.rpId()).isEqualTo("mesh.example.org");
        assertThat(r.origins()).isEqualTo(Set.of(new Origin("https://mesh.example.org")));
    }

    @Test
    void perRequest_subdomainAndParentOfAMeshDomain_areAccepted_asThePageHost() {
        WebAuthnRelyingParty rp = perRequest("", "https://id.example.org");
        assertThat(rp.resolve("https://admin.id.example.org").rpId()).isEqualTo("admin.id.example.org");
        assertThat(rp.resolve("https://example.org").rpId()).isEqualTo("example.org");
    }

    @Test
    void perRequest_rpDomainsAddBrands_andThePortIsKeptInTheOrigin() {
        WebAuthnRelyingParty rp = perRequest("Shop.Example.COM, other.test", "https://mesh.example.org");
        WebAuthnRelyingParty.Rp r = rp.resolve("https://shop.example.com:9443");
        assertThat(r.rpId()).isEqualTo("shop.example.com");
        assertThat(r.origins()).containsExactly(new Origin("https://shop.example.com:9443"));
        assertThat(rp.resolve("https://other.test").rpId()).isEqualTo("other.test");
    }

    @Test
    void perRequest_localhost_isAlwaysAccepted_evenOverHttp() {
        WebAuthnRelyingParty rp = perRequest("", "");
        WebAuthnRelyingParty.Rp r = rp.resolve("http://localhost:8080");
        assertThat(r.rpId()).isEqualTo("localhost");
        assertThat(r.origins()).containsExactly(new Origin("http://localhost:8080"));
    }

    @Test
    void perRequest_refusesWithAReason_ipOnionForeignPlainHttpAndNoOrigin() {
        WebAuthnRelyingParty rp = perRequest("", "https://mesh.example.org");
        assertThatThrownBy(() -> rp.resolve("https://127.0.0.1:9080"))
                .isInstanceOf(WebAuthnRelyingParty.Refused.class).hasMessageContaining("IP address");
        assertThatThrownBy(() -> rp.resolve("https://[::1]:9443"))
                .isInstanceOf(WebAuthnRelyingParty.Refused.class).hasMessageContaining("IP address");
        assertThatThrownBy(() -> rp.resolve(
                "https://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion"))
                .isInstanceOf(WebAuthnRelyingParty.Refused.class).hasMessageContaining("Tor");
        assertThatThrownBy(() -> rp.resolve("https://evil.test"))
                .isInstanceOf(WebAuthnRelyingParty.Refused.class).hasMessageContaining("not one of");
        assertThatThrownBy(() -> rp.resolve("http://mesh.example.org"))
                .isInstanceOf(WebAuthnRelyingParty.Refused.class).hasMessageContaining("https");
        assertThatThrownBy(() -> rp.resolve(null))
                .isInstanceOf(WebAuthnRelyingParty.Refused.class);
        assertThatThrownBy(() -> rp.resolve("null"))
                .isInstanceOf(WebAuthnRelyingParty.Refused.class);
    }

    @Test
    void perRequest_aLookalikeSuffix_isNotASubdomain() {
        WebAuthnRelyingParty rp = perRequest("", "https://example.org");
        assertThatThrownBy(() -> rp.resolve("https://evilexample.org"))
                .isInstanceOf(WebAuthnRelyingParty.Refused.class);
    }

    @Test
    void perRequest_aSingleLabelParent_isNeverAccepted() {
        WebAuthnRelyingParty rp = perRequest("", "https://mesh.example.org");
        assertThatThrownBy(() -> rp.resolve("https://org"))
                .isInstanceOf(WebAuthnRelyingParty.Refused.class);
    }

    @Test
    void perRequest_aLocalhostOrIpIssuer_addsNoDomain() {
        assertThat(perRequest("", "http://localhost:8000").domains()).isEmpty();
        assertThat(perRequest("", "http://10.0.0.5:8000").domains()).isEmpty();
    }
}
