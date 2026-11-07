package atom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jenkinschina.atom.sdk.Json;
import com.jenkinschina.atom.sdk.testing.Atom;
import com.jenkinschina.atom.sdk.testing.AtomResult;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The aws-cloudformation atom, started the way the runner starts it, against the fake CloudFormation in {@code tools/}
 * that checks the SigV4 signature itself.
 *
 * <p>These are the checks the old {@code tools/smoke.sh} made — create, update, a rejected signature, a no-op update
 * that is a success, a rollback that fails the step with the reason, {@code wait=false}, and the missing-template
 * refusal — written as JUnit.
 */
class AwsCloudformationIT {

    private static final String ACCESS = "AKIDEXAMPLE";
    private static final String SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    @Test
    @DisplayName("a stack that does not exist is created and polled to CREATE_COMPLETE")
    void createsAStack() throws Exception {
        try (Fake cf = Fake.start()) {
            AtomResult run = request(cf).run();

            run.assertOk();
            assertEquals("create", run.field("action"), "action:\n" + run);
            assertEquals("CREATE_COMPLETE", run.field("status"), "status:\n" + run);
            assertFalse(run.field("stackId").isBlank(), "the stack id should come back:\n" + run);
            assertTrue(run.console().contains("is CREATE_IN_PROGRESS"),
                    "the poll should have seen the in-progress state:\n" + run.console());
        }
    }

    @Test
    @DisplayName("the CreateStack request has numbered capabilities and parameters and the template in the body")
    void sendsTheCloudFormationRequestShape() throws Exception {
        try (Fake cf = Fake.start()) {
            AtomResult run = request(cf).run();

            run.assertOk();
            List<Map<String, Object>> entries = cf.entries(0);
            assertTrue(entries.stream().allMatch(entry -> Boolean.TRUE.equals(entry.get("ok"))),
                    "the endpoint refused a request: " + entries);

            Map<String, Object> create = entries.stream()
                    .filter(entry -> "CreateStack".equals(entry.get("action")))
                    .map(entry -> map(entry, "params"))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("no CreateStack was sent: " + entries));
            assertEquals("CAPABILITY_IAM", create.get("Capabilities.member.1"), create.toString());
            assertEquals("CAPABILITY_NAMED_IAM", create.get("Capabilities.member.2"), create.toString());
            assertEquals("Env", create.get("Parameters.member.1.ParameterKey"), create.toString());
            assertEquals("2", create.get("Parameters.member.2.ParameterValue"), create.toString());
            assertFalse(create.containsKey("templateBody"), "the form field name is lowercase: " + create);
            assertEquals("Resources: {}\n", create.get("TemplateBody"), create.toString());
        }
    }

    @Test
    @DisplayName("the second run finds the stack and updates it")
    void updatesAnExistingStack() throws Exception {
        try (Fake cf = Fake.start()) {
            request(cf).run().assertOk();
            long afterCreate = Files.size(cf.log);

            AtomResult run = request(cf).run();

            run.assertOk();
            assertEquals("update", run.field("action"), "action:\n" + run);
            assertEquals("UPDATE_COMPLETE", run.field("status"), "status:\n" + run);
            assertTrue(cf.entries(afterCreate).stream().anyMatch(entry -> "UpdateStack".equals(entry.get("action"))),
                    "the second run should call UpdateStack: " + cf.entries(afterCreate));
        }
    }

    @Test
    @DisplayName("a wrong secret is refused by the endpoint's own signature check, as a USER error")
    void rejectsAWrongSignature() throws Exception {
        try (Fake cf = Fake.start()) {
            AtomResult run = request(cf, ACCESS, "wrong-secret").run();

            run.assertRefused();
            assertTrue(run.file("output.json").contains("InvalidSignatureException"),
                    "AWS's error should surface:\n" + run);
            assertEquals("1", run.field("errorType"), "a refused request is a USER error:\n" + run);
        }
    }

    @Test
    @DisplayName("an update with no changes is a success, not a failure")
    void acceptsANoOpUpdate() throws Exception {
        try (Fake cf = Fake.start("--no-updates")) {
            AtomResult run = request(cf).run();

            run.assertOk();
            assertEquals("noop", run.field("action"), "action should be noop:\n" + run);
            assertTrue(run.console().contains("already up to date"), "the log should say why:\n" + run.console());
        }
    }

    @Test
    @DisplayName("a rollback fails the step and quotes the reason")
    void failsOnARollback() throws Exception {
        try (Fake cf = Fake.start("--rollback")) {
            AtomResult run = request(cf).run();

            assertNotEquals(0, run.exit(), "a rolled-back stack must fail the step:\n" + run);
            assertTrue(run.file("output.json").contains("ROLLBACK_COMPLETE"), "message:\n" + run);
            assertTrue(run.file("output.json").contains("the helper instance never came up"),
                    "the reason must be quoted:\n" + run);
        }
    }

    @Test
    @DisplayName("wait=false returns right after the call, with status started")
    void doesNotWait() throws Exception {
        try (Fake cf = Fake.start()) {
            AtomResult run = request(cf).input("wait", "false").run();

            run.assertOk();
            assertEquals("started", run.field("status"), "wait=false should report 'started':\n" + run);
        }
    }

    @Test
    @DisplayName("a stack without a template is refused")
    void refusesAStackWithoutATemplate() throws Exception {
        try (Fake cf = Fake.start()) {
            AtomResult run = request(cf).input("templateBody", "").run();

            run.assertRefused();
            assertTrue(run.field("message").contains("templateBody or templateUrl is required"), "message:\n" + run);
        }
    }

    /** The inputs the old smoke script wrote for every case. */
    private Atom request(Fake cf) throws Exception {
        return request(cf, ACCESS, SECRET);
    }

    private Atom request(Fake cf, String accessKey, String secretKey) throws Exception {
        return Atom.of()
                .file(".secrets.json", "{\"accessKey\": \"" + accessKey + "\", \"secretKey\": \"" + secretKey + "\"}")
                .input("region", "us-east-1")
                .input("stackName", "acme-net")
                .input("endpoint", cf.url)
                .input("templateBody", "Resources: {}\n")
                .input("parameters", "Env=prod,Size=2")
                .input("capabilities", "CAPABILITY_IAM,CAPABILITY_NAMED_IAM")
                .input("waitTimeoutSeconds", "60");
    }

    private static Map<String, Object> map(Map<String, Object> entry, String key) {
        Object value = entry.get(key);
        return value instanceof Map<?, ?> map ? cast(map) : Map.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cast(Map<?, ?> map) {
        return (Map<String, Object>) map;
    }

    private static Path module() {
        return Path.of(System.getProperty("atom.module", System.getProperty("user.dir")));
    }

    /** One fake CloudFormation on its own port; {@code --no-updates} and {@code --rollback} are the two modes. */
    private record Fake(Process process, String url, Path log) implements AutoCloseable {

        static Fake start(String... flags) throws Exception {
            int port;
            try (ServerSocket socket = new ServerSocket(0)) {
                port = socket.getLocalPort();
            }
            Path log = Files.createTempFile("cf-requests-", ".log");
            List<String> command = new ArrayList<>(List.of("python3",
                    module().resolve("tools/fake_cf.py").toString(), Integer.toString(port), log.toString(),
                    ACCESS, SECRET));
            command.addAll(List.of(flags));
            Path output = Files.createTempFile("cf-fake-", ".log");
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .redirectOutput(output.toFile())
                    .start();
            waitForPort(port, output);
            return new Fake(process, "http://127.0.0.1:" + port, log);
        }

        /** The requests the endpoint logged from {@code offset} on, as parsed JSON lines. */
        List<Map<String, Object>> entries(long offset) throws IOException {
            byte[] all = Files.readAllBytes(log);
            if (all.length <= offset) {
                return List.of();
            }
            String text = new String(all, (int) offset, all.length - (int) offset, StandardCharsets.UTF_8);
            List<Map<String, Object>> entries = new ArrayList<>();
            for (String line : text.split("\n")) {
                if (!line.isBlank()) {
                    entries.add(Json.parseObject(line));
                }
            }
            return entries;
        }

        @Override
        public void close() {
            process.destroy();
            try {
                process.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        private static void waitForPort(int port, Path output) throws Exception {
            long deadline = System.currentTimeMillis() + 10_000;
            while (System.currentTimeMillis() < deadline) {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress("127.0.0.1", port), 200);
                    return;
                } catch (IOException notYet) {
                    Thread.sleep(100);
                }
            }
            throw new IllegalStateException("the fake CloudFormation did not start: " + Files.readString(output));
        }
    }
}
