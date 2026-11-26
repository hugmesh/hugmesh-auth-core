package net.hugmesh.authcore.mfa;

import com.webauthn4j.data.client.Origin;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Which WebAuthn Relying Party a ceremony runs under (hugmesh-auth-core#39).
 *
 * <p><b>Why per request.</b> A browser only runs a WebAuthn ceremony when the RP ID is the
 * page's own host or a registrable suffix of it, and never for an IP address. One mesh is
 * reached at several addresses — {@code localhost}, its public domain (directly or through a
 * tunnel), every brand's own domain — so a single configured RP ID made passkeys work at one
 * address at most: a user on the public domain got options for {@code localhost} and the
 * browser refused without a word (2026-11-26).
 *
 * <p><b>Two modes.</b>
 * <ul>
 *   <li><b>Fixed</b> — {@code app.mfa.webauthn.rp-id} is set: exactly the pre-#39 behaviour
 *       (that RP ID and the {@code app.mfa.webauthn.origins} allowlist, for every request). A
 *       single-domain deployment that already sets it is unchanged.</li>
 *   <li><b>Per request</b> — {@code rp-id} is unset: the RP ID is the host of the page the
 *       request came from (the browser's {@code Origin} header, recorded by
 *       {@link WebAuthnOriginWebFilter}), accepted only when that host is {@code localhost} or
 *       belongs to one of the mesh's domains: the public sign-in issuer's host
 *       ({@code spring.security.oauth2.resourceserver.jwt.issuer-uri}) and every entry of
 *       {@code app.mfa.webauthn.rp-domains}. "Belongs" = equal, a subdomain, or the parent of
 *       a domain (at least two labels). The expected origin is that page origin exactly.</li>
 * </ul>
 *
 * <p><b>Why trusting the {@code Origin} header is safe.</b> It only chooses WHICH allowed RP
 * the server demands; WebAuthn4J then checks that the authenticator signed for that RP ID's
 * hash and that the signed client data names that origin. A forged header from a non-browser
 * client can at most ask for another of the mesh's own domains, where the attacker holds no
 * credential.
 *
 * <p><b>Refusals</b> ({@link Refused}, mapped to a 400 the page shows): an IP address (browsers
 * never accept one), a {@code .onion} host (no WebAuthn over the onion in the browsers the mesh
 * targets), a host that is none of the mesh's domains, and a request with no origin at all.
 */
@Component
public class WebAuthnRelyingParty {

    /** One resolved Relying Party: the RP ID and the origins a response may carry. */
    public record Rp(String rpId, Set<Origin> origins) {
        /** An immutable copy: a resolved RP is shared across a ceremony and never changes. */
        public Rp {
            origins = origins == null ? Set.of() : Set.copyOf(origins);
        }
    }

    /** A request the per-request mode cannot run a ceremony for, with the sentence why. */
    public static class Refused extends RuntimeException {
        public Refused(String message) {
            super(message);
        }
    }

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern HOST = Pattern.compile(
            "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$");

    private final Rp fixed;                 // non-null in fixed mode
    private final List<String> domains;     // the mesh's domains (per-request mode)

    public WebAuthnRelyingParty(
            @Value("${app.mfa.webauthn.rp-id:}") String rpId,
            @Value("${app.mfa.webauthn.origins:}") String originsCsv,
            @Value("${app.mfa.webauthn.rp-domains:}") String rpDomainsCsv,
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") String issuerUri) {
        if (rpId != null && !rpId.isBlank()) {
            Set<Origin> origins = new LinkedHashSet<>();
            for (String o : csv(originsCsv)) {
                origins.add(new Origin(o));
            }
            if (origins.isEmpty()) {
                origins.add(new Origin("https://localhost"));
            }
            this.fixed = new Rp(rpId.trim(), Collections.unmodifiableSet(origins));
            this.domains = List.of();
        } else {
            this.fixed = null;
            List<String> d = new ArrayList<>();
            String issuerHost = hostOf(issuerUri);
            if (issuerHost != null && isDomainName(issuerHost) && !"localhost".equals(issuerHost)) {
                d.add(issuerHost);
            }
            for (String x : csv(rpDomainsCsv)) {
                String h = x.toLowerCase(Locale.ROOT);
                if (isDomainName(h) && !d.contains(h)) {
                    d.add(h);
                }
            }
            this.domains = List.copyOf(d);
        }
    }

    /** True when {@code app.mfa.webauthn.rp-id} is set (the pre-#39 single-RP behaviour). */
    public boolean isFixed() {
        return fixed != null;
    }

    /** The fixed RP ID, or {@code null} in per-request mode. */
    public String fixedRpId() {
        return fixed == null ? null : fixed.rpId();
    }

    /** The fixed origins, or an empty set in per-request mode. */
    public Set<Origin> fixedOrigins() {
        return fixed == null ? Set.of() : fixed.origins();
    }

    /** The mesh domains the per-request mode accepts (besides {@code localhost}). */
    public List<String> domains() {
        return domains;
    }

    /**
     * The Relying Party for a request whose browser origin is {@code requestOrigin} (the
     * {@code Origin} header, e.g. {@code https://admin.example.org:9443}). In fixed mode the
     * argument is ignored. Throws {@link Refused} when per-request mode cannot serve it.
     */
    public Rp resolve(String requestOrigin) {
        if (fixed != null) {
            return fixed;
        }
        if (requestOrigin == null || requestOrigin.isBlank() || "null".equals(requestOrigin.trim())) {
            throw new Refused("Passkeys need the page's address, and this request did not say "
                    + "which page it came from. Reload the page and try again.");
        }
        URI u;
        try {
            u = URI.create(requestOrigin.trim());
        } catch (IllegalArgumentException e) {
            throw new Refused("Passkeys cannot be used from this page address.");
        }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        String host = u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT);
        if (host.startsWith("[") || host.contains(":") || IPV4.matcher(host).matches()) {
            throw new Refused("Passkeys cannot be used at an IP address (" + host + "): browsers "
                    + "only allow them on a domain name. Open this page at the mesh's domain "
                    + "name, or at localhost on this computer.");
        }
        if (host.endsWith(".onion")) {
            throw new Refused("Passkeys are not available over the mesh's Tor address. Use an "
                    + "authenticator app here, or add a passkey at the mesh's domain name.");
        }
        boolean local = "localhost".equals(host) || host.endsWith(".localhost");
        if (!local && !"https".equals(scheme)) {
            throw new Refused("Passkeys need a secure (https) page.");
        }
        if (!local && !belongsToMesh(host)) {
            throw new Refused("Passkeys cannot be used at " + host + ": it is not one of this "
                    + "mesh's domains.");
        }
        String origin = scheme + "://" + host + (u.getPort() > 0 ? ":" + u.getPort() : "");
        return new Rp(local ? "localhost" : host, Set.of(new Origin(origin)));
    }

    /** Equal to a mesh domain, a subdomain of one, or the parent of one (two+ labels). */
    boolean belongsToMesh(String host) {
        if (!isDomainName(host)) {
            return false;
        }
        for (String d : domains) {
            if (host.equals(d) || host.endsWith("." + d)) {
                return true;
            }
            if (d.endsWith("." + host) && host.indexOf('.') > 0) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDomainName(String h) {
        return h != null && h.length() <= 253 && HOST.matcher(h).matches()
                && !IPV4.matcher(h).matches();
    }

    private static String hostOf(String uri) {
        if (uri == null || uri.isBlank()) {
            return null;
        }
        try {
            String h = URI.create(uri.trim()).getHost();
            return h == null ? null : h.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static List<String> csv(String s) {
        List<String> out = new ArrayList<>();
        if (s != null) {
            for (String x : s.split(",")) {
                String t = x.trim();
                if (!t.isEmpty()) {
                    out.add(t);
                }
            }
        }
        return out;
    }
}
