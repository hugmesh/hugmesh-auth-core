package systems.snapdragon.authcore.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The PROD-profile {@link InternalSurfaceBootGuard} fail-fast contract — it REFUSES TO BOOT
 * (throws during {@code afterSingletonsInstantiated}, aborting context refresh) when the
 * privilege-bearing {@code /bff/internal/**} surface would be served without mTLS in
 * production, and is a clean pass when mTLS is in force. The guard bean is only ever created
 * under the prod profile ({@code @Profile("!dev & !test")}), so dev/test never reach it.
 */
class InternalSurfaceBootGuardTest {

    @Test
    void refusesToBoot_whenSslDisabled() {
        InternalSurfaceBootGuard guard = new InternalSurfaceBootGuard(false, "need");
        assertThatThrownBy(guard::afterSingletonsInstantiated)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("REFUSING TO BOOT")
                .hasMessageContaining("/bff/internal/**");
    }

    @Test
    void refusesToBoot_whenClientAuthNotRequired() {
        InternalSurfaceBootGuard guard = new InternalSurfaceBootGuard(true, "none");
        assertThatThrownBy(guard::afterSingletonsInstantiated)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("client-auth");
    }

    @Test
    void refusesToBoot_whenClientAuthOptional() {
        // client-auth=want is NOT enough — the surface must REQUIRE a client cert.
        InternalSurfaceBootGuard guard = new InternalSurfaceBootGuard(true, "want");
        assertThatThrownBy(guard::afterSingletonsInstantiated)
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void boots_whenMtlsInForce() {
        InternalSurfaceBootGuard guard = new InternalSurfaceBootGuard(true, "need");
        assertThatCode(guard::afterSingletonsInstantiated).doesNotThrowAnyException();
    }

    @Test
    void boots_whenMtlsInForce_clientAuthCaseAndWhitespaceTolerant() {
        InternalSurfaceBootGuard guard = new InternalSurfaceBootGuard(true, "  NEED  ");
        assertThatCode(guard::afterSingletonsInstantiated).doesNotThrowAnyException();
    }
}
