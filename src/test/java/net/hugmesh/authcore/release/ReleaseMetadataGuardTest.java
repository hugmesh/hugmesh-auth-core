package net.hugmesh.authcore.release;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
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
 * <p><b>Why this parses the workflow instead of grepping it.</b> The first cut of this class
 * string-matched {@code release.yml}, and two adversarial reviews showed the same failure
 * mode from opposite ends: a guard that matches one SPELLING of a config file fails OPEN on
 * every other spelling of the same meaning. Both were measured green against a reverted
 * workflow. (a) The trigger check blacklisted only {@code "\n  push:"} and
 * {@code "\n    push:"}, so the flow forms {@code on: [push, workflow_dispatch]} and
 * {@code on: {workflow_dispatch: {}, push: {tags: [v*]}}}, the quoted key {@code "push":},
 * and the {@code release:}/{@code schedule:} triggers all sailed through — every one of them
 * publishes without a human. (b) The deploy-target check ran on the RAW file text, so
 * deleting {@code -DaltDeploymentRepository} from the {@code run:} line stayed green as long
 * as the flag survived in the 10-line comment block that sits directly above it — i.e. the
 * exact defect this guard exists to pin, silently restored. So: both checks now read the
 * PARSED document. Comments do not exist after parsing, and every YAML spelling of a
 * trigger collapses to the same key set. Note {@code on:} is a YAML 1.1 boolean, which is
 * why {@link #triggerNames} looks up {@link Boolean#TRUE} as well as {@code "on"}.
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

    /** The only trigger this workflow may carry. Anything else publishes without a human. */
    private static final Set<String> ONLY_ALLOWED_TRIGGER = Set.of("workflow_dispatch");

    private static final String RELEASE_WORKFLOW = ".github/workflows/release.yml";

    private static Path repoRoot() {
        return Path.of(System.getProperty("basedir", System.getProperty("user.dir", ".")));
    }

    private static String read(String relative) throws Exception {
        Path p = repoRoot().resolve(relative);
        assertThat(p).as("%s must exist — it is part of the release contract", relative).exists();
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    /** The release workflow as a parsed document. Comments are gone; spelling is normalised. */
    private static Map<?, ?> releaseWorkflow() throws Exception {
        Object doc = new Yaml(new SafeConstructor(new LoaderOptions())).load(read(RELEASE_WORKFLOW));
        assertThat(doc)
                .as("%s must parse as a YAML mapping — GitHub Actions cannot run it otherwise",
                        RELEASE_WORKFLOW)
                .isInstanceOf(Map.class);
        return (Map<?, ?>) doc;
    }

    /**
     * The workflow's trigger names, whatever YAML shape they were written in.
     *
     * <p>{@code on:} is an unquoted YAML 1.1 boolean, so the parser hands it back under the key
     * {@link Boolean#TRUE}; {@code "on":} comes back as the string. Both are accepted here, and
     * the value may be a scalar ({@code on: push}), a sequence ({@code on: [push, ...]} or a
     * block list) or a mapping ({@code on: {push: {...}}} or a block mapping) — all three
     * collapse to the same set of names.
     */
    private static Set<String> triggerNames(Map<?, ?> workflow) {
        Object on = workflow.containsKey(Boolean.TRUE) ? workflow.get(Boolean.TRUE) : workflow.get("on");
        assertThat(on)
                .as("%s declares no `on:` block — a workflow with no trigger is not the shape "
                        + "this guard knows how to check, so fail rather than pass vacuously",
                        RELEASE_WORKFLOW)
                .isNotNull();

        Set<String> names = new LinkedHashSet<>();
        if (on instanceof Map<?, ?> m) {
            m.keySet().forEach(k -> names.add(String.valueOf(k)));
        } else if (on instanceof Iterable<?> it) {
            it.forEach(e -> {
                // A block sequence entry may itself be a mapping: `- push: {branches: [main]}`.
                if (e instanceof Map<?, ?> em) {
                    em.keySet().forEach(k -> names.add(String.valueOf(k)));
                } else {
                    names.add(String.valueOf(e));
                }
            });
        } else {
            names.add(String.valueOf(on));
        }
        // `on: [on, push]` would round-trip a boolean back out; normalise it to its spelling.
        names.remove("true");
        if (String.valueOf(on).equals("true")) {
            names.add("on");
        }
        return names;
    }

    /**
     * Every shell command the workflow actually runs, in order. Read off the parsed document,
     * so a flag that survives only in a YAML comment is NOT here — which is the point.
     */
    private static List<String> runCommands(Map<?, ?> workflow) {
        List<String> commands = new ArrayList<>();
        Object jobs = workflow.get("jobs");
        assertThat(jobs).as("%s declares no jobs", RELEASE_WORKFLOW).isInstanceOf(Map.class);
        for (Object job : ((Map<?, ?>) jobs).values()) {
            if (!(job instanceof Map<?, ?> jobMap)) {
                continue;
            }
            Object steps = jobMap.get("steps");
            if (!(steps instanceof Iterable<?> stepList)) {
                continue;
            }
            for (Object step : stepList) {
                if (step instanceof Map<?, ?> stepMap && stepMap.get("run") instanceof String run) {
                    commands.add(run);
                }
            }
        }
        return commands;
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
        List<String> runs = runCommands(releaseWorkflow());
        // `\bdeploy\b` is case-sensitive on purpose: it matches the `deploy` lifecycle phase and
        // the `deploy:deploy-file` goal, and does NOT match `-DaltDeploymentRepository`.
        List<String> deploys = runs.stream().filter(c -> c.matches("(?s).*\\bdeploy\\b.*")).toList();
        assertThat(deploys)
                .as("%s runs no deploy command at all — either the publish step was removed, or "
                        + "it is no longer a `run:` step this guard can see. Parsed run commands: %s",
                        RELEASE_WORKFLOW, runs)
                .isNotEmpty();

        for (String deploy : deploys) {
            assertThat(deploy)
                    .as("the deploy step must override the inherited distributionManagement. "
                            + "Without %s it deploys to server id 'gitlab-maven' at the literal, "
                            + "uninterpolated ${env.CI_API_V4_URL}/... URL, with credentials that "
                            + "were provisioned for the 'github' id. See RELEASING.md §3.1. "
                            + "Offending command: %s",
                            EXPECTED_DEPLOY_OVERRIDE, deploy)
                    .contains(EXPECTED_DEPLOY_OVERRIDE);
            // The override must name THIS repository, not a hand-typed sibling coordinate.
            assertThat(deploy)
                    .as("the altDeploymentRepository URL must resolve to this repo — "
                            + "${{ github.repository }} or the literal hugmesh/hugmesh-auth-core. "
                            + "Offending command: %s", deploy)
                    .satisfiesAnyOf(
                            s -> assertThat(s).contains(EXPECTED_DEPLOY_OVERRIDE + "${{ github.repository }}"),
                            s -> assertThat(s).contains(EXPECTED_DEPLOY_OVERRIDE + "hugmesh/hugmesh-auth-core"));
        }
    }

    @Test
    @DisplayName("the release workflow is workflow_dispatch-only — it never publishes on its own")
    void releaseWorkflowNeverFiresOnPushOrTag() throws Exception {
        Set<String> triggers = triggerNames(releaseWorkflow());
        // An ALLOWLIST, not a blacklist of push spellings: any trigger other than
        // workflow_dispatch — push, pull_request, release, schedule, workflow_run,
        // repository_dispatch — publishes whatever version pom.xml happens to hold at the
        // time, over an already-published coordinate.
        assertThat(triggers)
                .as("release.yml must stay workflow_dispatch-only; it declares %s. "
                        + "Publish-on-merge is exactly what made 2.4.1 a mutable coordinate and "
                        + "forced the 2.4.2 re-pin. If a new trigger is deliberate, widen "
                        + "ONLY_ALLOWED_TRIGGER in the same change and say why in RELEASING.md.",
                        triggers)
                .containsExactlyInAnyOrderElementsOf(ONLY_ALLOWED_TRIGGER);
    }

    // ===================================================================================
    // Decision 27 (hugmesh-generator#347, 2026-09-17): "B for the mechanism, A prepared".
    // The source-build mechanism is untouched; the publish path is real but unfired. These
    // four checks pin the shape of that prepared path, and in particular pin the ONE thing
    // that would quietly break every developer and every cold compose build if someone
    // "simplified" it: the GitHub Packages URL living anywhere except the CI-only settings
    // file. maven.pkg.github.com answers 401 to an UNAUTHENTICATED GET (measured
    // 2026-09-17, and 401 again with a classic token that lacks read:packages), so a
    // <repositories> entry in pom.xml is not a convenience, it is an outage.
    // ===================================================================================

    /** The CI-only Maven settings file. The only place a GitHub Packages URL may appear. */
    private static final String CI_SETTINGS = ".github/maven-ci-settings.xml";

    /** What every maven invocation in the release workflow must pass. */
    private static final String CI_SETTINGS_FLAG = "-s " + CI_SETTINGS;

    /** The one-trigger orchestrator that fires all four links in build order. */
    private static final String CHAIN_WORKFLOW = ".github/workflows/release-chain.yml";

    private static final String PACKAGES_HOST = "maven.pkg.github.com";

    /** The upstreams this build must RESOLVE, in the order they have to be published. */
    private static final List<String> UPSTREAM_REPOS =
            List.of("hugmesh-build-config", "hugmesh-parent", "hugmesh-commons");

    /** The full chain, in build order — what release-chain.yml must dispatch. */
    private static final List<String> CHAIN_REPOS =
            List.of("hugmesh-build-config", "hugmesh-parent", "hugmesh-commons", "hugmesh-auth-core");

    /** Any YAML file under .github/workflows, parsed. */
    private static Map<?, ?> parseWorkflow(String relative) throws Exception {
        Object doc = new Yaml(new SafeConstructor(new LoaderOptions())).load(read(relative));
        assertThat(doc).as("%s must parse as a YAML mapping", relative).isInstanceOf(Map.class);
        return (Map<?, ?>) doc;
    }

    /** Every workflow file in the repo, not just release.yml. */
    private static List<Path> workflowFiles() throws Exception {
        Path dir = repoRoot().resolve(".github/workflows");
        assertThat(dir).as(".github/workflows must exist — the publish path lives there").isDirectory();
        try (Stream<Path> paths = Files.list(dir)) {
            List<Path> files = paths.filter(Files::isRegularFile)
                    .filter(f -> {
                        String n = f.getFileName().toString().toLowerCase(Locale.ROOT);
                        return n.endsWith(".yml") || n.endsWith(".yaml");
                    })
                    .sorted(Comparator.comparing(Path::toString))
                    .toList();
            assertThat(files).as("no workflow files found — this guard would pass vacuously").isNotEmpty();
            return files;
        }
    }

    /** {@code <id>}/{@code <url>} pairs of every element of the given tag in an XML file. */
    private static Map<String, String> xmlEntries(String relative, String tag) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setNamespaceAware(false);
        Document doc = f.newDocumentBuilder().parse(new File(repoRoot().resolve(relative).toString()));
        Map<String, String> out = new java.util.LinkedHashMap<>();
        NodeList nodes = doc.getElementsByTagName(tag);
        for (int i = 0; i < nodes.getLength(); i++) {
            Node n = nodes.item(i);
            String id = null;
            String url = "";
            NodeList kids = n.getChildNodes();
            for (int k = 0; k < kids.getLength(); k++) {
                Node kid = kids.item(k);
                if (kid.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                }
                if ("id".equals(kid.getNodeName())) {
                    id = kid.getTextContent().trim();
                } else if ("url".equals(kid.getNodeName())) {
                    url = kid.getTextContent().trim();
                }
            }
            if (id != null) {
                out.put(id, url);
            }
        }
        return out;
    }

    @Test
    @DisplayName("no workflow in this repo fires on its own — not just release.yml")
    void everyWorkflowIsDispatchOnly() throws Exception {
        for (Path file : workflowFiles()) {
            String relative = repoRoot().relativize(file).toString();
            Set<String> triggers = triggerNames(parseWorkflow(relative));
            assertThat(triggers)
                    .as("%s declares triggers %s. Every workflow in this repo publishes or can "
                            + "publish an immutable coordinate, so all of them stay "
                            + "workflow_dispatch-only — the guard that protected release.yml "
                            + "alone would have let a second workflow arrive with a push "
                            + "trigger and nobody notice.", relative, triggers)
                    .containsExactlyInAnyOrderElementsOf(ONLY_ALLOWED_TRIGGER);
        }
    }

    @Test
    @DisplayName("every maven command in release.yml passes the CI-only settings file")
    void releaseWorkflowResolvesThroughTheCiSettingsFile() throws Exception {
        assertThat(repoRoot().resolve(CI_SETTINGS))
                .as("%s must exist — it is the whole resolution route for a CI build. Without "
                        + "it `verify` cannot resolve this pom's own <parent> (the effective "
                        + "repository list is Maven Central alone and net.hugmesh:* is 404 "
                        + "there).", CI_SETTINGS)
                .exists();

        List<String> runs = runCommands(releaseWorkflow());
        List<String> mavens = runs.stream()
                .filter(c -> c.matches("(?s).*(^|\\s)\\./mvnw(\\s|$).*") || c.matches("(?s).*(^|\\s)mvn(\\s|$).*"))
                .toList();
        assertThat(mavens)
                .as("%s runs no maven command at all — the publish step is gone or is no longer "
                        + "a `run:` step this guard can read. Parsed commands: %s",
                        RELEASE_WORKFLOW, runs)
                .isNotEmpty();

        for (String cmd : mavens) {
            assertThat(cmd)
                    .as("every maven invocation in %s must pass `%s`. `-s` REPLACES the user "
                            + "settings file, so a command that omits it gets neither the "
                            + "upstream repositories (build fails at parent resolution) nor the "
                            + "`github` server entry (deploy uploads unauthenticated). "
                            + "Offending command: %s", RELEASE_WORKFLOW, CI_SETTINGS_FLAG, cmd)
                    .contains(CI_SETTINGS_FLAG);
        }
    }

    @Test
    @DisplayName("the CI settings file declares each upstream as BOTH a repository and a pluginRepository")
    void ciSettingsCoversTheWholeUpstreamChain() throws Exception {
        Map<String, String> repositories = xmlEntries(CI_SETTINGS, "repository");
        Map<String, String> pluginRepositories = xmlEntries(CI_SETTINGS, "pluginRepository");
        Map<String, String> servers = xmlEntries(CI_SETTINGS, "server");

        for (String upstream : UPSTREAM_REPOS) {
            String expectedUrl = "https://" + PACKAGES_HOST + "/hugmesh/" + upstream;
            assertThat(repositories.values())
                    .as("%s declares no <repository> for %s. GitHub Packages is per-repository "
                            + "(there is no org-wide Maven endpoint), so every upstream link is "
                            + "its own URL. Declared: %s", CI_SETTINGS, upstream, repositories)
                    .contains(expectedUrl);
            assertThat(pluginRepositories.values())
                    .as("%s declares no <pluginRepository> for %s. Maven resolves a PLUGIN's "
                            + "<dependencies> from the PLUGIN repositories: hugmesh-parent puts "
                            + "net.hugmesh:hugmesh-build-config on the PMD/Checkstyle/SpotBugs "
                            + "plugin classpaths, so a repositories-only file resolves the parent "
                            + "POM and then dies at `verify` on the ruleset jar. Declared: %s",
                            CI_SETTINGS, upstream, pluginRepositories)
                    .contains(expectedUrl);
        }

        assertThat(servers.keySet())
                .as("%s must carry a <server> for every repository id it declares, or Maven "
                        + "sends no credential and GitHub Packages answers 401 even for a read. "
                        + "Repository ids: %s; server ids: %s",
                        CI_SETTINGS, repositories.keySet(), servers.keySet())
                .containsAll(repositories.keySet())
                .containsAll(pluginRepositories.keySet());

        assertThat(servers)
                .as("%s must also carry the `github` <server>: `-s` replaces the settings file "
                        + "actions/setup-java generates, so without this entry the deploy step's "
                        + "-DaltDeploymentRepository=github::default::... uploads with no "
                        + "credential. Server ids: %s", CI_SETTINGS, servers.keySet())
                .containsKey("github");
    }

    @Test
    @DisplayName("the GitHub Packages URL never leaks into the normal, unauthenticated build")
    void packagesRepositoryStaysOutOfThePomAndTheGitlabSettings() throws Exception {
        for (String everydayFile : List.of("pom.xml", "settings.xml")) {
            assertThat(read(everydayFile))
                    .as("%s names %s. That host answers 401 to an unauthenticated GET (measured "
                            + "2026-09-17; 401 again with a token lacking read:packages), so "
                            + "declaring it here breaks every developer `./mvnw verify` and "
                            + "hugmesh-generator/tests/stack/m2-bootstrap.sh, which is how the "
                            + "compose lane builds this library and which operator decision 27 "
                            + "deliberately KEEPS as the mechanism. The URL belongs in %s and "
                            + "nowhere else.", everydayFile, PACKAGES_HOST, CI_SETTINGS)
                    .doesNotContain(PACKAGES_HOST);
        }
    }

    @Test
    @DisplayName("the chain workflow dispatches all four links, in build order, on one credential")
    void releaseChainFiresTheWholeChainInOrder() throws Exception {
        Map<?, ?> chain = parseWorkflow(CHAIN_WORKFLOW);
        String script = String.join("\n", runCommands(chain));
        assertThat(script)
                .as("%s runs no shell at all — the one-trigger chain is not there", CHAIN_WORKFLOW)
                .isNotBlank();

        int previous = -1;
        for (String repo : CHAIN_REPOS) {
            int at = script.indexOf("hugmesh/" + repo);
            assertThat(at)
                    .as("%s never names hugmesh/%s. The chain must dispatch all four links: "
                            + "%s.", CHAIN_WORKFLOW, repo, CHAIN_REPOS)
                    .isGreaterThanOrEqualTo(0);
            assertThat(at)
                    .as("%s names hugmesh/%s out of build order. Order is %s — publishing a "
                            + "link before the artifacts it resolves against exist fails as an "
                            + "unrelated-looking 'Could not resolve net.hugmesh:...' several "
                            + "steps later.", CHAIN_WORKFLOW, repo, CHAIN_REPOS)
                    .isGreaterThan(previous);
            previous = at;
        }

        assertThat(read(CHAIN_WORKFLOW))
                .as("%s must read the cross-repo credential from secrets.RELEASE_CHAIN_TOKEN. "
                        + "secrets.GITHUB_TOKEN is scoped to THIS repository and cannot dispatch "
                        + "a workflow in the other three, so a chain wired to it fails at the "
                        + "first hop with a 404 that reads like a missing workflow.",
                        CHAIN_WORKFLOW)
                .contains("RELEASE_CHAIN_TOKEN");
    }
}
