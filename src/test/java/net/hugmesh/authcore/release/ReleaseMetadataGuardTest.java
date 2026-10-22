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
 *   <li><b>The release workflow never publishes on a merge.</b> Publish-on-every-merge is
 *       what made 2.4.1 a mutable coordinate and forced the 2.4.2 re-pin (the GitLab
 *       {@code deploy:maven} job re-deploys at whatever version the pom holds). Since the beta
 *       scheme (2026-10-21) the workflow fires on {@code workflow_dispatch} and on a push of a
 *       {@code v*} TAG only, never on a branch push; the deploy runs only when the version
 *       guard has matched the tag to {@code pom.xml}. Any other trigger has to be a deliberate
 *       edit that also updates this guard.</li>
 *   <li><b>Publish jobs never reach the self-hosted runner from a pull request.</b> Every
 *       job's {@code runs-on} is either a literal hosted label or the one guarded
 *       {@code RUNS_ON_PUBLISH} expression, and nothing reads the old {@code RUNS_ON}
 *       variable.</li>
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

    /**
     * A version as written in the docs: a semver triple, optionally with a pre-release part
     * ({@code 2.6.0-beta.1}). The pre-release part is captured WITH the triple, so a heading
     * for {@code 2.6.0-beta.1} can never be read back as {@code 2.6.0}.
     */
    private static final String DOC_VERSION = "(\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.]+)?)";

    /** Newest CHANGELOG entry: a level-2 heading whose first token is a version. */
    private static final Pattern CHANGELOG_VERSION =
            Pattern.compile("(?m)^##\\s+" + DOC_VERSION + "(?=\\s|$)");

    /** The README's single self-declared version, e.g. {@code - **Version 2.6.0-beta.1** on the ...}. */
    private static final Pattern README_VERSION =
            Pattern.compile("\\*\\*Version\\s+" + DOC_VERSION + "\\*\\*");

    /**
     * The only shape a published version may take: {@code MAJOR.MINOR.PATCH} or
     * {@code MAJOR.MINOR.PATCH-beta.N} (beta scheme, 2026-10-21). No SNAPSHOT, no build
     * metadata, no other pre-release label.
     */
    private static final Pattern PUBLISHABLE_VERSION =
            Pattern.compile("\\d+\\.\\d+\\.\\d+(?:-beta\\.[1-9]\\d*)?");

    /** The one deploy coordinate that overrides the inherited GitLab distributionManagement. */
    private static final String EXPECTED_DEPLOY_OVERRIDE =
            "-DaltDeploymentRepository=github::default::https://maven.pkg.github.com/";

    /**
     * The only triggers a publishing workflow may carry: a human dispatch, and a push that
     * is restricted to {@code v*} TAGS (see {@link #assertPushIsTagOnly}). Anything else
     * publishes without a human decision.
     */
    private static final Set<String> ONLY_ALLOWED_TRIGGER = Set.of("workflow_dispatch", "push");

    /** The triggers release.yml must carry exactly: dispatch (re-run path) and the tag push. */
    private static final Set<String> RELEASE_TRIGGERS = Set.of("workflow_dispatch", "push");

    /**
     * The one runner expression a publish job may use (SCHEME.md 3.1): the self-hosted runner
     * from RUNS_ON_PUBLISH only for a non-PR event on main or a version tag, hosted otherwise.
     */
    static final String PUBLISH_RUNS_ON = "${{ fromJSON(github.event_name != 'pull_request' "
            + "&& github.event_name != 'pull_request_target' && (github.ref == 'refs/heads/main' "
            + "|| startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/tags/studio-v')) "
            + "&& vars.RUNS_ON_PUBLISH || '\"ubuntu-latest\"') }}";

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

    /** The raw value of one trigger ({@code on.<name>}), or {@code null} when absent or bare. */
    private static Object triggerValue(Map<?, ?> workflow, String name) {
        Object on = workflow.containsKey(Boolean.TRUE) ? workflow.get(Boolean.TRUE) : workflow.get("on");
        if (on instanceof Map<?, ?> m) {
            return m.get(name);
        }
        if (on instanceof Iterable<?> it) {
            for (Object e : it) {
                if (e instanceof Map<?, ?> em && em.containsKey(name)) {
                    return em.get(name);
                }
            }
        }
        return null;
    }

    /**
     * A {@code push} trigger on a publishing workflow must be restricted to {@code v*} tags:
     * a mapping whose ONLY key is {@code tags}, every pattern starting with {@code v}. A bare
     * {@code push} (no filter), any {@code branches}/{@code branches-ignore}, a
     * {@code tags-ignore} or a {@code paths} filter all let a branch push publish.
     */
    private static void assertPushIsTagOnly(String relative, Map<?, ?> workflow) {
        if (!triggerNames(workflow).contains("push")) {
            return;
        }
        Object push = triggerValue(workflow, "push");
        assertThat(push)
                .as("%s: `push` is unfiltered (value %s), so EVERY branch push publishes "
                        + "whatever pom.xml holds. Restrict it to `tags: ['v*']`.", relative, push)
                .isInstanceOf(Map.class);
        Map<?, ?> pushMap = (Map<?, ?>) push;
        assertThat(pushMap.keySet().stream().map(String::valueOf).toList())
                .as("%s: `push` may carry ONLY a `tags` filter; it declares %s. A `branches`, "
                        + "`branches-ignore`, `tags-ignore` or `paths` key makes a branch push "
                        + "(a merge to main) publish an immutable coordinate.", relative, pushMap.keySet())
                .containsExactly("tags");
        Object tags = pushMap.get("tags");
        List<String> patterns = new ArrayList<>();
        if (tags instanceof Iterable<?> it) {
            it.forEach(t -> patterns.add(String.valueOf(t)));
        } else {
            patterns.add(String.valueOf(tags));
        }
        assertThat(patterns)
                .as("%s: push.tags must list at least one pattern", relative)
                .isNotEmpty()
                .allSatisfy(t -> assertThat(t)
                        .as("%s: push.tags pattern '%s' must start with 'v' (version tags only; "
                                + "'*' or '**' would publish on any tag)", relative, t)
                        .startsWith("v"));
    }

    @Test
    @DisplayName("the release workflow fires only on a dispatch or a v* tag push — never on a merge")
    void releaseWorkflowNeverFiresOnABranchPush() throws Exception {
        Map<?, ?> workflow = releaseWorkflow();
        Set<String> triggers = triggerNames(workflow);
        // An ALLOWLIST, not a blacklist of push spellings: any trigger other than these two —
        // pull_request, release, schedule, workflow_run, repository_dispatch — publishes
        // whatever version pom.xml happens to hold at the time, over an already-published
        // coordinate.
        assertThat(triggers)
                .as("release.yml must fire on exactly workflow_dispatch and a tag push; it declares "
                        + "%s. Publish-on-merge is exactly what made 2.4.1 a mutable coordinate and "
                        + "forced the 2.4.2 re-pin. If a new trigger is deliberate, change "
                        + "RELEASE_TRIGGERS in the same change and say why in RELEASING.md.",
                        triggers)
                .containsExactlyInAnyOrderElementsOf(RELEASE_TRIGGERS);
        assertPushIsTagOnly(RELEASE_WORKFLOW, workflow);
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

    // ===================================================================================
    // Cross-repo package reads (added 2026-09-18, after adversarial review of the decision
    // 27 round). The prepared chain reads GitHub Packages published from OTHER repositories.
    // secrets.GITHUB_TOKEN is scoped to the repository whose workflow is running, and GitHub
    // does not grant it cross-repository package access by default, so the build must present
    // a token carrying read:packages (PACKAGES_READ_TOKEN; decision 90a = B; the per-package
    // "Manage Actions access" grant is not the plan). The first cut did not, and the maven
    // error is "Could not resolve net.hugmesh:..." — the exact string RELEASING.md teaches a
    // reader to interpret as "the upstream is not published yet". These checks pin the fix.
    // ===================================================================================

    /** The env var pair the upstream <server> entries read their credential from. */
    private static final String UPSTREAM_ACTOR = "${env.UPSTREAM_PACKAGES_ACTOR}";
    private static final String UPSTREAM_TOKEN = "${env.UPSTREAM_PACKAGES_TOKEN}";

    /** Every step of a workflow, as parsed maps. */
    private static List<Map<?, ?>> steps(Map<?, ?> workflow) {
        List<Map<?, ?>> out = new ArrayList<>();
        if (workflow.get("jobs") instanceof Map<?, ?> jobs) {
            for (Object job : jobs.values()) {
                if (job instanceof Map<?, ?> jobMap && jobMap.get("steps") instanceof Iterable<?> list) {
                    for (Object step : list) {
                        if (step instanceof Map<?, ?> stepMap) {
                            out.add(stepMap);
                        }
                    }
                }
            }
        }
        return out;
    }

    /** {@code <server>} id to its literal [username, password] in a settings file. */
    private static Map<String, List<String>> serverCredentials(String relative) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setNamespaceAware(false);
        Document doc = f.newDocumentBuilder().parse(new File(repoRoot().resolve(relative).toString()));
        Map<String, List<String>> out = new java.util.LinkedHashMap<>();
        NodeList servers = doc.getElementsByTagName("server");
        for (int i = 0; i < servers.getLength(); i++) {
            String id = null;
            String user = "";
            String pass = "";
            NodeList kids = servers.item(i).getChildNodes();
            for (int k = 0; k < kids.getLength(); k++) {
                Node kid = kids.item(k);
                if (kid.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                }
                switch (kid.getNodeName()) {
                    case "id" -> id = kid.getTextContent().trim();
                    case "username" -> user = kid.getTextContent().trim();
                    case "password" -> pass = kid.getTextContent().trim();
                    default -> { }
                }
            }
            if (id != null) {
                out.put(id, List.of(user, pass));
            }
        }
        assertThat(out).as("%s declares no <server> entries at all", relative).isNotEmpty();
        return out;
    }

    /** Recursively: does any {@code permissions:} block in this document mention packages? */
    private static boolean grantsPackagesPermission(Object node) {
        if (node instanceof Map<?, ?> m) {
            Object perms = m.get("permissions");
            if (perms instanceof Map<?, ?> pm && pm.containsKey("packages")) {
                return true;
            }
            if ("write-all".equals(String.valueOf(perms))) {
                return true;
            }
            for (Object v : m.values()) {
                if (grantsPackagesPermission(v)) {
                    return true;
                }
            }
        } else if (node instanceof Iterable<?> it) {
            for (Object v : it) {
                if (grantsPackagesPermission(v)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Can this workflow publish an immutable coordinate, directly or by dispatching something
     * that does?
     *
     * <p>The classifier is deliberately lopsided: EXEMPTION is hard to obtain and easy to lose.
     * A workflow counts as publishing if ANY of these hold — a parsed {@code run:} command
     * invokes the {@code deploy} phase/goal; a parsed {@code run:} command dispatches another
     * workflow ({@code gh workflow run}); any {@code permissions:} block in it mentions
     * {@code packages}; or the RAW file text names {@code maven.pkg.github.com} at all,
     * comments included. The raw-text clause is on the INCLUDING side on purpose — a comment
     * that mentions the registry makes a workflow stricter, never looser, which is the
     * opposite of the fail-open direction this class was burned by before.
     *
     * <p><b>Why this is not simply "every workflow".</b> Measured 2026-09-18: the
     * all-workflows form failed a plain {@code ci.yml} running {@code ./mvnw test} on
     * {@code pull_request}, with the message "Every workflow in this repo publishes or can
     * publish an immutable coordinate" — which is false of a test-only workflow. This repo has
     * no pre-merge CI workflow yet, so that guard would have gone red in the face of the first
     * person wiring one up (the 116-of-126 pre-merge gate programme), for a reason with
     * nothing to do with releases. A guard that blocks the correct change is a guard people
     * delete.
     */
    private static boolean canPublish(String relative) throws Exception {
        if (read(relative).contains(PACKAGES_HOST)) {
            return true;
        }
        Map<?, ?> workflow = parseWorkflow(relative);
        if (grantsPackagesPermission(workflow)) {
            return true;
        }
        for (String cmd : runCommands(workflow)) {
            if (cmd.matches("(?s).*\\bdeploy\\b.*") || cmd.contains("workflow run")) {
                return true;
            }
        }
        return false;
    }

    @Test
    @DisplayName("every workflow that CAN publish fires only on dispatch or a v* tag — and release.yml is always classified as one")
    void everyPublishingWorkflowIsDispatchOrTagOnly() throws Exception {
        List<String> publishing = new ArrayList<>();
        List<String> exempt = new ArrayList<>();
        for (Path file : workflowFiles()) {
            String relative = repoRoot().relativize(file).toString().replace('\\', '/');
            if (!canPublish(relative)) {
                exempt.add(relative);
                continue;
            }
            publishing.add(relative);
            Map<?, ?> workflow = parseWorkflow(relative);
            Set<String> triggers = triggerNames(workflow);
            assertThat(triggers)
                    .as("%s can publish an immutable coordinate and declares triggers %s. "
                            + "Only workflow_dispatch and a v*-tag-only push are allowed; any other "
                            + "trigger — pull_request, release, schedule, workflow_run, "
                            + "repository_dispatch — republishes whatever version pom.xml happens "
                            + "to hold over a coordinate that is already out there. If a new "
                            + "trigger is deliberate, widen ONLY_ALLOWED_TRIGGER in the same change "
                            + "and say why in RELEASING.md. (Workflows this run treated as "
                            + "NON-publishing, and therefore free to carry any trigger: %s — see "
                            + "canPublish().)",
                            relative, triggers, exempt)
                    .contains("workflow_dispatch")
                    .isSubsetOf(ONLY_ALLOWED_TRIGGER);
            assertPushIsTagOnly(relative, workflow);
        }
        assertThat(publishing)
                .as("canPublish() exempted the release workflow itself, so this guard just passed "
                        + "vacuously over the one file it exists for. Classified as publishing: %s; "
                        + "exempt: %s.", publishing, exempt)
                .contains(RELEASE_WORKFLOW, CHAIN_WORKFLOW);
    }

    @Test
    @DisplayName("cross-repo package reads do NOT ride on the repository-scoped GITHUB_TOKEN")
    void upstreamReadsCarryTheirOwnOverridableCredential() throws Exception {
        Map<String, List<String>> servers = serverCredentials(CI_SETTINGS);

        assertThat(servers.get("github"))
                .as("the DEPLOY server must keep the automatic ${env.GITHUB_TOKEN}. A workflow "
                        + "may always write packages for the repository it runs in, so requiring "
                        + "an operator-held secret for the deploy half would be a regression, not "
                        + "a fix. Declared: %s", servers)
                .containsExactly("${env.GITHUB_ACTOR}", "${env.GITHUB_TOKEN}");

        for (Map.Entry<String, List<String>> e : servers.entrySet()) {
            if ("github".equals(e.getKey())) {
                continue;
            }
            assertThat(e.getValue())
                    .as("<server id=%s> authenticates a READ of packages published from ANOTHER "
                            + "repository. secrets.GITHUB_TOKEN is scoped to the repository whose "
                            + "workflow is running; GitHub does not grant it cross-repo package "
                            + "access unless that package names this repository under 'Manage "
                            + "Actions access'. Wiring this server to ${env.GITHUB_TOKEN} makes "
                            + "the whole chain depend on a click nobody wrote down, and it fails "
                            + "as 'Could not resolve net.hugmesh:...' — the exact string "
                            + "RELEASING.md teaches a reader to interpret as 'the upstream is not "
                            + "published yet', so the first real run gets MISDIAGNOSED. Use %s / "
                            + "%s, which release.yml injects from secrets.PACKAGES_READ_TOKEN with "
                            + "a GITHUB_TOKEN fallback. See RELEASING.md 6.2.",
                            e.getKey(), UPSTREAM_ACTOR, UPSTREAM_TOKEN)
                    .containsExactly(UPSTREAM_ACTOR, UPSTREAM_TOKEN);
        }
    }

    @Test
    @DisplayName("release.yml injects that read credential into every settings-file maven step, overridably")
    void releaseWorkflowInjectsTheUpstreamReadCredential() throws Exception {
        int checked = 0;
        for (Map<?, ?> step : steps(parseWorkflow(RELEASE_WORKFLOW))) {
            if (!(step.get("run") instanceof String run) || !run.contains(CI_SETTINGS_FLAG)) {
                continue;
            }
            checked++;
            Object env = step.get("env");
            assertThat(env)
                    .as("step '%s' runs maven with %s but declares no env: block, so "
                            + "${env.UPSTREAM_PACKAGES_TOKEN} in the settings file expands to "
                            + "nothing and every upstream read goes out unauthenticated (401).",
                            step.get("name"), CI_SETTINGS_FLAG)
                    .isInstanceOf(Map.class);
            Map<?, ?> envMap = (Map<?, ?>) env;
            String token = String.valueOf(envMap.get("UPSTREAM_PACKAGES_TOKEN"));
            List<String> envKeys = envMap.keySet().stream().map(String::valueOf).toList();
            assertThat(envKeys)
                    .as("step '%s' must inject UPSTREAM_PACKAGES_ACTOR and "
                            + "UPSTREAM_PACKAGES_TOKEN. Declared: %s",
                            step.get("name"), envKeys)
                    .contains("UPSTREAM_PACKAGES_ACTOR", "UPSTREAM_PACKAGES_TOKEN");
            assertThat(token)
                    .as("step '%s' wires UPSTREAM_PACKAGES_TOKEN to '%s'. It must offer the "
                            + "operator's read:packages PAT and fall back to the automatic token: "
                            + "${{ secrets.PACKAGES_READ_TOKEN || secrets.GITHUB_TOKEN }}. "
                            + "Hardcoding secrets.GITHUB_TOKEN alone leaves the cross-repo read "
                            + "with no working credential and no operator override.", step.get("name"), token)
                    .contains("secrets.PACKAGES_READ_TOKEN")
                    .contains("secrets.GITHUB_TOKEN");
        }
        assertThat(checked)
                .as("no step in %s runs maven with %s — this guard just passed vacuously",
                        RELEASE_WORKFLOW, CI_SETTINGS_FLAG)
                .isGreaterThan(0);
    }

    @Test
    @DisplayName("the cross-repo read is preflighted, and the read route is documented")
    void crossRepoPackageReadIsPreflightedAndDocumented() throws Exception {
        List<Map<?, ?>> preflights = steps(parseWorkflow(RELEASE_WORKFLOW)).stream()
                .filter(s -> String.valueOf(s.get("name")).toLowerCase(Locale.ROOT).startsWith("preflight"))
                .toList();
        assertThat(preflights)
                .as("%s has no Preflight step. Without it, a credential that cannot read an "
                        + "upstream registry surfaces only as maven's 'Could not resolve "
                        + "net.hugmesh:...', which is indistinguishable from 'not published yet' "
                        + "and sends the operator off to re-publish something that is already "
                        + "there. The preflight exists to name that failure correctly.",
                        RELEASE_WORKFLOW)
                .hasSize(1);

        String script = String.valueOf(preflights.get(0).get("run"));
        for (String upstream : UPSTREAM_REPOS) {
            assertThat(script)
                    .as("the preflight never probes hugmesh/%s, so a credential that cannot read "
                            + "that upstream gets past it. Upstreams: %s", upstream, UPSTREAM_REPOS)
                    .contains(upstream);
        }
        assertThat(script)
                .as("the preflight must tell 401/403 (cannot authenticate) apart from 404 "
                        + "(nothing published, OR published and masked). Collapsing them is the "
                        + "misdiagnosis this step exists to prevent. Script: %s", script)
                .contains("401").contains("403").contains("404");
        assertThat(String.valueOf(preflights.get(0).get("env")))
                .as("the preflight must probe with the SAME credential maven will use, or a green "
                        + "preflight proves nothing about the build that follows it.")
                .contains("UPSTREAM_PACKAGES_TOKEN");

        String releasing = read("RELEASING.md");
        assertThat(releasing)
                .as("RELEASING.md must name the per-package 'Manage Actions access' grant as "
                        + "*not the plan* (decision 90a = B). It is documented so a reader is told "
                        + "that route is not chosen.")
                .contains("Manage Actions access");
        assertThat(releasing)
                .as("RELEASING.md must name PACKAGES_READ_TOKEN — the read route, kept by "
                        + "decision 90a = B.")
                .contains("PACKAGES_READ_TOKEN");
    }

    // ===================================================================================
    // Beta scheme (2026-10-21): the tag is the publish decision, the version guard matches it
    // to pom.xml, a published version is never overwritten, a beta is a prerelease GitHub
    // Release that is never "latest", and publish jobs reach the self-hosted runner only for
    // a non-PR event on main or a version tag.
    // ===================================================================================

    /** {@code jobs:} of a parsed workflow, by job id. */
    private static Map<String, Map<?, ?>> jobs(Map<?, ?> workflow) {
        Map<String, Map<?, ?>> out = new java.util.LinkedHashMap<>();
        if (workflow.get("jobs") instanceof Map<?, ?> js) {
            js.forEach((k, v) -> {
                if (v instanceof Map<?, ?> m) {
                    out.put(String.valueOf(k), m);
                }
            });
        }
        assertThat(out).as("workflow declares no jobs").isNotEmpty();
        return out;
    }

    private static List<Map<?, ?>> jobSteps(Map<?, ?> job) {
        List<Map<?, ?>> out = new ArrayList<>();
        if (job.get("steps") instanceof Iterable<?> list) {
            for (Object step : list) {
                if (step instanceof Map<?, ?> m) {
                    out.add(m);
                }
            }
        }
        return out;
    }

    private static List<String> needs(Map<?, ?> job) {
        Object n = job.get("needs");
        List<String> out = new ArrayList<>();
        if (n instanceof Iterable<?> it) {
            it.forEach(e -> out.add(String.valueOf(e)));
        } else if (n != null) {
            out.add(String.valueOf(n));
        }
        return out;
    }

    private static final String RELEASE_KIND_CONDITION = "needs.version.outputs.kind == 'release'";

    @Test
    @DisplayName("the deploy runs only after the version guard matched a v* tag to pom.xml, and never over a published version")
    void deployRunsOnlyForAGuardedVersionTag() throws Exception {
        Map<String, Map<?, ?>> jobs = jobs(releaseWorkflow());
        assertThat(jobs)
                .as("%s must have a `version` job: it is the guard that decides whether this run "
                        + "may publish at all", RELEASE_WORKFLOW)
                .containsKey("version");

        String guard = String.join("\n", jobSteps(jobs.get("version")).stream()
                .map(st -> String.valueOf(st.get("run"))).toList());
        assertThat(guard)
                .as("the version guard must read pom.xml, refuse a -SNAPSHOT, compare the tag "
                        + "(minus its leading v) with the pom version, and allow main only as a "
                        + "non-publishing run. Script: %s", guard)
                .contains("pom.xml")
                .contains("-SNAPSHOT")
                .contains("#v}")
                .contains("refs/heads/main")
                .contains("kind=release")
                .contains("kind=main");

        int deploys = 0;
        for (Map.Entry<String, Map<?, ?>> job : jobs.entrySet()) {
            List<Map<?, ?>> steps = jobSteps(job.getValue());
            int refuseAt = -1;
            for (int i = 0; i < steps.size(); i++) {
                Map<?, ?> step = steps.get(i);
                String name = String.valueOf(step.get("name"));
                if (name.toLowerCase(Locale.ROOT).contains("already published")) {
                    refuseAt = i;
                    assertThat(String.valueOf(step.get("if")))
                            .as("step '%s' must run on release runs", name)
                            .contains(RELEASE_KIND_CONDITION);
                    assertThat(String.valueOf(step.get("run")))
                            .as("step '%s' must STOP (exit 1) when the version answers 200", name)
                            .contains("200)")
                            .contains("exit 1");
                }
                if (!(step.get("run") instanceof String run) || !run.matches("(?s).*\\bdeploy\\b.*")) {
                    continue;
                }
                deploys++;
                assertThat(String.valueOf(step.get("if")))
                        .as("deploy step '%s' in job '%s' must run only when the version guard "
                                + "classified the run as a release (a matched v* tag): `if: %s`. "
                                + "Without it a dispatch on main republishes pom.xml's version.",
                                name, job.getKey(), RELEASE_KIND_CONDITION)
                        .contains(RELEASE_KIND_CONDITION);
                assertThat(needs(job.getValue()))
                        .as("job '%s' deploys, so it must `needs: version`", job.getKey())
                        .contains("version");
                assertThat(refuseAt)
                        .as("job '%s' deploys without first refusing an already-published version "
                                + "(a step whose name says 'already published', before the deploy). "
                                + "A published coordinate is immutable.", job.getKey())
                        .isBetween(0, i - 1);
            }
        }
        assertThat(deploys).as("%s runs no deploy step — this guard passed vacuously", RELEASE_WORKFLOW)
                .isGreaterThan(0);
    }

    @Test
    @DisplayName("a beta becomes a prerelease GitHub Release that is never 'latest', created only by a release run")
    void githubReleaseIsAPrereleaseAndNeverLatestForABeta() throws Exception {
        Map<?, ?> workflow = releaseWorkflow();
        assertThat(String.valueOf(workflow.get("permissions")))
                .as("top-level permissions must stay read-only; only the release job may write contents")
                .doesNotContain("write");

        int creates = 0;
        for (Map.Entry<String, Map<?, ?>> job : jobs(workflow).entrySet()) {
            for (Map<?, ?> step : jobSteps(job.getValue())) {
                if (!(step.get("run") instanceof String run) || !run.contains("gh release create")) {
                    continue;
                }
                creates++;
                assertThat(String.valueOf(job.getValue().get("if")))
                        .as("job '%s' creates a GitHub Release, so it must run only on a release run",
                                job.getKey())
                        .contains(RELEASE_KIND_CONDITION);
                assertThat(needs(job.getValue()))
                        .as("job '%s' must wait for the publish job: a Release must never exist for "
                                + "a version that failed to deploy", job.getKey())
                        .contains("publish");
                assertThat(run)
                        .as("the beta release command must pass --verify-tag, --prerelease and "
                                + "--latest=false: a beta is never the repository's latest release. %s", run)
                        .contains("--verify-tag")
                        .contains("--prerelease --latest=false")
                        .contains("PRERELEASE");
            }
        }
        assertThat(creates).as("%s never creates a GitHub Release", RELEASE_WORKFLOW).isGreaterThan(0);
    }

    @Test
    @DisplayName("publish jobs reach the self-hosted runner only through the guarded RUNS_ON_PUBLISH expression")
    void publishJobsNeverReachTheSelfHostedRunnerFromAPullRequest() throws Exception {
        for (Path file : workflowFiles()) {
            String relative = repoRoot().relativize(file).toString().replace('\\', '/');
            String raw = read(relative);
            assertThat(raw)
                    .as("%s reads the old `vars.RUNS_ON` variable. It is set to the self-hosted "
                            + "runner on most repos and is not limited to main or tags, so a pull "
                            + "request — from a fork, once the repo is public — would run on this "
                            + "host. Use the RUNS_ON_PUBLISH expression (SCHEME.md 3.1).", relative)
                    .doesNotContainPattern("vars\\.RUNS_ON(?!_PUBLISH)");

            Map<?, ?> workflow = parseWorkflow(relative);
            Set<String> triggers = triggerNames(workflow);
            boolean prReachable = triggers.contains("pull_request") || triggers.contains("pull_request_target");
            for (Map.Entry<String, Map<?, ?>> job : jobs(workflow).entrySet()) {
                Object runsOn = job.getValue().get("runs-on");
                assertThat(runsOn)
                        .as("%s job '%s': runs-on must be a single string (a literal hosted label or "
                                + "the guarded expression), not %s", relative, job.getKey(), runsOn)
                        .isInstanceOf(String.class);
                String r = (String) runsOn;
                boolean literalHosted = !r.contains("${{") && !r.contains("self-hosted");
                if (prReachable) {
                    assertThat(literalHosted)
                            .as("%s runs on pull requests, so job '%s' must name a hosted runner "
                                    + "literally (ubuntu-latest); it says '%s'", relative, job.getKey(), r)
                            .isTrue();
                } else {
                    assertThat(literalHosted || r.equals(PUBLISH_RUNS_ON))
                            .as("%s job '%s': runs-on must be a literal hosted label or exactly "
                                    + "%s; it says '%s'", relative, job.getKey(), PUBLISH_RUNS_ON, r)
                            .isTrue();
                }
            }
        }
    }

    @Test
    @DisplayName("pom.xml builds a publishable version and pins every net.hugmesh coordinate exactly")
    void pomVersionAndNetHugmeshPinsArePublishable() throws Exception {
        assertThat(projectVersion())
                .as("pom.xml's version must be MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-beta.N (no "
                        + "SNAPSHOT, no build metadata): it becomes an immutable coordinate and a "
                        + "v<version> git tag")
                .matches(PUBLISHABLE_VERSION);

        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setNamespaceAware(false);
        Document doc = f.newDocumentBuilder().parse(new File(repoRoot().resolve("pom.xml").toString()));
        int pins = 0;
        for (String tag : List.of("parent", "dependency")) {
            NodeList nodes = doc.getElementsByTagName(tag);
            for (int i = 0; i < nodes.getLength(); i++) {
                String group = "";
                String artifact = "";
                String version = "";
                NodeList kids = nodes.item(i).getChildNodes();
                for (int k = 0; k < kids.getLength(); k++) {
                    Node kid = kids.item(k);
                    switch (kid.getNodeName()) {
                        case "groupId" -> group = kid.getTextContent().trim();
                        case "artifactId" -> artifact = kid.getTextContent().trim();
                        case "version" -> version = kid.getTextContent().trim();
                        default -> { }
                    }
                }
                if (!"net.hugmesh".equals(group)) {
                    continue;
                }
                pins++;
                assertThat(version)
                        .as("net.hugmesh:%s is pinned to '%s'. Dependents pin a literal published "
                                + "version (MAJOR.MINOR.PATCH or -beta.N): no SNAPSHOT, no range, no "
                                + "property, no LATEST/RELEASE", artifact, version)
                        .matches(PUBLISHABLE_VERSION);
            }
        }
        assertThat(pins).as("pom.xml names no net.hugmesh coordinate — this check passed vacuously")
                .isGreaterThanOrEqualTo(3);
    }

    @Test
    @DisplayName("on the self-hosted runner the publish job never writes into the person's own ~/.m2")
    void publishJobLeavesTheRunnerUsersMavenHomeAlone() throws Exception {
        Map<?, ?> workflow = releaseWorkflow();
        int setupJava = 0;
        for (Map.Entry<String, Map<?, ?>> job : jobs(workflow).entrySet()) {
            for (Map<?, ?> step : jobSteps(job.getValue())) {
                if (!String.valueOf(step.get("uses")).startsWith("actions/setup-java@")) {
                    continue;
                }
                setupJava++;
                Map<?, ?> with = step.get("with") instanceof Map<?, ?> m ? m : Map.of();
                assertThat(String.valueOf(with.get("settings-path")))
                        .as("job '%s': actions/setup-java writes settings.xml into ~/.m2 by default, "
                                + "REPLACING the runner user's own file on the self-hosted runner. "
                                + "Set `settings-path: ${{ runner.temp }}`.", job.getKey())
                        .contains("runner.temp");
                assertThat(String.valueOf(with.get("cache")))
                        .as("job '%s': setup-java `cache: maven` restores an archive over the runner "
                                + "user's ~/.m2/repository on the self-hosted runner", job.getKey())
                        .isNotEqualTo("maven");
            }
        }
        assertThat(setupJava).as("%s has no actions/setup-java step — this guard passed vacuously",
                RELEASE_WORKFLOW).isGreaterThan(0);

        List<String> mvn = runCommands(workflow).stream().filter(c -> c.contains("./mvnw")).toList();
        assertThat(mvn).as("%s runs no ./mvnw command — this guard passed vacuously", RELEASE_WORKFLOW)
                .isNotEmpty()
                .allSatisfy(c -> assertThat(c)
                        .as("every Maven run must use the job-private local repository "
                                + "(-Dmaven.repo.local=\"${MAVEN_LOCAL_REPO}\"), never the runner user's "
                                + "~/.m2/repository, where a hand-built upstream would satisfy the build "
                                + "without proving the registry holds it: %s", c)
                        .contains("-Dmaven.repo.local=\"${MAVEN_LOCAL_REPO}\""));
    }

    @Test
    @DisplayName("the chain dispatches each link on its v<version> tag, never on a branch")
    void releaseChainDispatchesEachLinkOnItsVersionTag() throws Exception {
        String script = String.join("\n", runCommands(parseWorkflow(CHAIN_WORKFLOW)));
        assertThat(script)
                .as("%s must dispatch each link ON ITS TAG (a dispatch on a branch only verifies) "
                        + "and derive the tag from that repo's pom.xml version", CHAIN_WORKFLOW)
                .contains("tag=\"v$version\"")
                .contains("--ref \"$tag\"")
                .contains("git/ref/tags/$tag")
                .contains("gh release view \"$tag\"");
    }
}
