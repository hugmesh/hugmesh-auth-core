package net.hugmesh.authcore.release;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the RELEASE METADATA of this library — the things that decide what a published
 * coordinate contains and where it is published to. None of this is reachable from a unit
 * test of the Java code, and every one of these has already gone wrong here at least once.
 *
 * <ol>
 *   <li><b>Three version statements, one value.</b> {@code pom.xml}, the
 *       {@code **Version X.Y.Z**} line in {@code README.md} and the newest heading in
 *       {@code CHANGELOG.md} must agree. 2.5.1 landed in the pom at {@code fe2bf3a} and in
 *       the README only at {@code dba8a82} — a window in which the repo advertised a version
 *       it was not building.</li>
 *   <li><b>The deploy target is GitHub Packages, explicitly.</b> This pom declares no
 *       {@code <distributionManagement>}, so it inherits {@code hugmesh-parent}'s, whose URL
 *       is the literal, uninterpolated
 *       {@code ${env.CI_API_V4_URL}/projects/${env.CI_PROJECT_ID}/packages/maven} anywhere
 *       outside GitLab CI. A deploy step without an explicit override therefore aims a
 *       {@code gitlab-maven} server id at a non-URL while the runner holds credentials for
 *       the {@code github} id only. See RELEASING.md §3.1.</li>
 *   <li><b>The release workflow never fires on its own.</b> Publish-on-every-merge is what
 *       made 2.4.1 a mutable coordinate and forced the 2.4.2 re-pin (the GitLab
 *       {@code deploy:maven} job re-deploys at whatever version the pom holds). The GitHub
 *       workflow stays {@code workflow_dispatch}-only; adding a push/tag trigger has to be a
 *       deliberate edit that also updates this guard.</li>
 * </ol>
 *
 * <p>Reads the repository files directly: surefire runs with the project basedir as its
 * working directory, and {@code basedir} is also exported as a system property.
 */
class ReleaseMetadataGuardTest {

    /** Newest CHANGELOG entry: a level-2 heading whose first token is a semver triple. */
    private static final Pattern CHANGELOG_VERSION =
            Pattern.compile("(?m)^##\\s+(\\d+\\.\\d+\\.\\d+)\\b");

    /** The README's single self-declared version, e.g. {@code - **Version 2.5.1** on the ...}. */
    private static final Pattern README_VERSION =
            Pattern.compile("\\*\\*Version\\s+(\\d+\\.\\d+\\.\\d+)\\*\\*");

    /** The one deploy coordinate that overrides the inherited GitLab distributionManagement. */
    private static final String EXPECTED_DEPLOY_OVERRIDE =
            "-DaltDeploymentRepository=github::default::https://maven.pkg.github.com/";

    private static Path repoRoot() {
        return Path.of(System.getProperty("basedir", System.getProperty("user.dir", ".")));
    }

    private static String read(String relative) throws Exception {
        Path p = repoRoot().resolve(relative);
        assertThat(p).as("%s must exist — it is part of the release contract", relative).exists();
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    /** The project's OWN version: the {@code <version>} that is a direct child of {@code <project>}. */
    private static String projectVersion() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setNamespaceAware(false);
        Document doc = f.newDocumentBuilder().parse(new File(repoRoot().resolve("pom.xml").toString()));
        Element project = doc.getDocumentElement();
        NodeList children = project.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            // Direct child only — a nested <version> under <parent> or a <dependency> must not win.
            if (n.getNodeType() == Node.ELEMENT_NODE && "version".equals(n.getNodeName())) {
                return n.getTextContent().trim();
            }
        }
        throw new AssertionError("pom.xml declares no project-level <version>");
    }

    private static String firstMatch(Pattern p, String haystack, String what) {
        Matcher m = p.matcher(haystack);
        assertThat(m.find()).as("%s must be present and semver-shaped", what).isTrue();
        return m.group(1);
    }

    @Test
    @DisplayName("CHANGELOG's newest entry is the version the pom actually builds")
    void changelogTopEntryMatchesPomVersion() throws Exception {
        String pom = projectVersion();
        String changelog = firstMatch(CHANGELOG_VERSION, read("CHANGELOG.md"), "CHANGELOG.md's newest ## heading");
        assertThat(changelog)
                .as("CHANGELOG.md's newest entry (%s) must name pom.xml's version (%s) — "
                        + "a release with no notes, or notes for a version nobody builds, is how "
                        + "a coordinate gets published with the wrong contents", changelog, pom)
                .isEqualTo(pom);
    }

    @Test
    @DisplayName("README's self-declared version is the version the pom actually builds")
    void readmeVersionMatchesPomVersion() throws Exception {
        String pom = projectVersion();
        String readme = firstMatch(README_VERSION, read("README.md"), "README.md's **Version X.Y.Z** line");
        assertThat(readme)
                .as("README.md says **Version %s** but pom.xml builds %s — these drifted once "
                        + "already (pom at fe2bf3a, README at dba8a82)", readme, pom)
                .isEqualTo(pom);
    }

    @Test
    @DisplayName("the release workflow deploys to GitHub Packages, not the inherited GitLab target")
    void releaseWorkflowOverridesTheInheritedGitlabDeployTarget() throws Exception {
        String wf = read(".github/workflows/release.yml");
        assertThat(wf)
                .as("the deploy step must override the inherited distributionManagement. Without "
                        + "%s it deploys to server id 'gitlab-maven' at the literal, "
                        + "uninterpolated ${env.CI_API_V4_URL}/... URL, with credentials that were "
                        + "provisioned for the 'github' id. See RELEASING.md §3.1.",
                        EXPECTED_DEPLOY_OVERRIDE)
                .contains(EXPECTED_DEPLOY_OVERRIDE);
        // The override must name THIS repository, not a hand-typed sibling coordinate.
        assertThat(wf)
                .as("the altDeploymentRepository URL must resolve to this repo — "
                        + "${{ github.repository }} or the literal hugmesh/hugmesh-auth-core")
                .satisfiesAnyOf(
                        s -> assertThat(s).contains(EXPECTED_DEPLOY_OVERRIDE + "${{ github.repository }}"),
                        s -> assertThat(s).contains(EXPECTED_DEPLOY_OVERRIDE + "hugmesh/hugmesh-auth-core"));
    }

    @Test
    @DisplayName("the release workflow is workflow_dispatch-only — it never publishes on its own")
    void releaseWorkflowNeverFiresOnPushOrTag() throws Exception {
        String wf = read(".github/workflows/release.yml");
        String body = wf.lines()
                .filter(l -> !l.stripLeading().startsWith("#"))
                .reduce("", (a, b) -> a + "\n" + b);
        assertThat(body)
                .as("release.yml must stay workflow_dispatch-only. Publish-on-merge is exactly "
                        + "what made 2.4.1 a mutable coordinate and forced the 2.4.2 re-pin.")
                .contains("workflow_dispatch");
        assertThat(body)
                .as("release.yml gained a push/tag trigger — that republishes whatever version "
                        + "pom.xml happens to hold, over an already-published coordinate. If this "
                        + "is deliberate, update this guard in the same change.")
                .doesNotContain("\n  push:")
                .doesNotContain("\n    push:");
    }
}
