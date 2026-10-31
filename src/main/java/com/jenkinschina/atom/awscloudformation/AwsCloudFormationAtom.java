package com.jenkinschina.atom.awscloudformation;

import com.jenkinschina.atom.sdk.AtomContext;
import com.jenkinschina.atom.sdk.AtomResult;
import com.jenkinschina.atom.sdk.AtomTask;
import com.jenkinschina.atom.sdk.ErrorType;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Creates or updates a CloudFormation stack and waits for it to settle.
 *
 * <p>CloudFormation's API is the older Query protocol: form-encoded parameters, an {@code Action} name, and XML back.
 * That is less fashionable than JSON but it is stable, and it means this atom needs nothing beyond the signer.
 *
 * <p>Two behaviours matter more than the call itself: an update that changes nothing ("No updates are to be
 * performed") is a success, not an error, and a stack that rolls back has to fail the step with the reason, because a
 * green build after a rollback is how a broken deploy ships.
 */
public class AwsCloudFormationAtom implements AtomTask {

    private static final String SERVICE = "cloudformation";
    private static final String VERSION = "2010-05-15";

    @Override
    public AtomResult run(AtomContext context) throws Exception {
        String region = context.getParam("region", "").trim();
        String accessKey = secret(context, "accessKey");
        String secretKey = secret(context, "secretKey");
        String sessionToken = secret(context, "sessionToken");
        String stackName = context.getParam("stackName", "").trim();
        String templateBody = context.getParam("templateBody", "");
        String templateUrl = context.getParam("templateUrl", "").trim();
        String parameters = context.getParam("parameters", "").trim();
        String capabilities = context.getParam("capabilities", "").trim();
        String endpointOverride = context.getParam("endpoint", "").trim();
        boolean wait = context.getBooleanParam("wait", true);
        int waitSeconds = Math.max(10, Math.min(context.getIntParam("waitTimeoutSeconds", 1800), 7200));
        int timeoutSeconds = Math.max(5, Math.min(context.getIntParam("timeoutSeconds", 60), 600));

        if (region.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40001, "region is required");
        }
        if (accessKey.isEmpty() || secretKey.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40002, "accessKey and secretKey are required (use a credential)");
        }
        if (stackName.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40003, "stackName is required");
        }
        if (templateBody.isBlank() && templateUrl.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40004,
                    "either templateBody or templateUrl is required (a stack needs a template)");
        }

        String endpoint = endpointOverride.isEmpty()
                ? "https://" + SERVICE + "." + region + ".amazonaws.com"
                : endpointOverride.replaceAll("/+$", "");
        String host = URI.create(endpoint).getAuthority();
        AwsSigner signer = new AwsSigner(accessKey, secretKey, sessionToken, region, SERVICE);
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(timeoutSeconds)).build();

        boolean exists = false;
        Reply described = call(client, signer, endpoint, host, "DescribeStacks",
                Map.of("StackName", stackName), timeoutSeconds);
        if (described.ok()) {
            exists = true;
        } else if (!"ValidationError".equals(described.errorCode()) && described.status != 400) {
            // a rejected signature or a missing permission is the caller's problem, not AWS being down
            ErrorType type = described.status == 400 || described.status == 403 ? ErrorType.USER
                    : ErrorType.THIRD_PART;
            return AtomResult.error(type, 40005, "DescribeStacks failed: " + described.describe());
        }

        Map<String, String> body = new LinkedHashMap<>();
        body.put("StackName", stackName);
        if (!templateUrl.isEmpty()) {
            body.put("TemplateURL", templateUrl);
        } else {
            body.put("TemplateBody", templateBody);
        }
        if (!capabilities.isEmpty()) {
            // "CAPABILITY_IAM,CAPABILITY_NAMED_IAM": CF wants numbered members, not a comma list
            List<String> values = new ArrayList<>();
            for (String part : capabilities.split(",")) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    values.add(trimmed);
                }
            }
            for (int i = 0; i < values.size(); i++) {
                body.put("Capabilities.member." + (i + 1), values.get(i));
            }
        }
        int index = 0;
        for (Map.Entry<String, String> parameter : parseParameters(parameters).entrySet()) {
            index++;
            body.put("Parameters.member." + index + ".ParameterKey", parameter.getKey());
            body.put("Parameters.member." + index + ".ParameterValue", parameter.getValue());
        }

        String action = exists ? "UpdateStack" : "CreateStack";
        String actionLabel = exists ? "update" : "create";
        Reply change = call(client, signer, endpoint, host, action, body, timeoutSeconds);
        String stackId = "";
        if (!change.ok() && "ValidationError".equals(change.errorCode())
                && change.message().toLowerCase(Locale.ROOT).contains("no updates are to be performed")) {
            context.log("[cf] " + stackName + " is already up to date");
            return AtomResult.success()
                    .data("action", "noop")
                    .data("status", "unchanged")
                    .data("stackName", stackName)
                    .data("stackId", idOf(described));
        }
        if (!change.ok()) {
            ErrorType type = change.status == 400 || change.status == 403 ? ErrorType.USER : ErrorType.THIRD_PART;
            String hint = change.message().contains("does not exist")
                    ? " (the stack is in a state that forbids updates; roll it back or delete it first)" : "";
            return AtomResult.error(type, 40006, action + " on " + stackName + " failed: " + change.describe() + hint);
        }
        stackId = idOf(change);
        context.log("[cf] " + action + " started for " + stackName + (stackId.isEmpty() ? "" : " (" + stackId + ")"));

        if (!wait) {
            return AtomResult.success()
                    .data("action", actionLabel)
                    .data("status", "started")
                    .data("stackName", stackName)
                    .data("stackId", stackId);
        }

        long deadline = System.currentTimeMillis() + waitSeconds * 1000L;
        String status = "IN_PROGRESS";
        String reason = "";
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(5000);
            Reply polled = call(client, signer, endpoint, host, "DescribeStacks",
                    Map.of("StackName", stackName), timeoutSeconds);
            if (!polled.ok()) {
                return AtomResult.error(ErrorType.THIRD_PART, 40007, "DescribeStacks failed while waiting: "
                        + polled.describe()).data("stackId", stackId);
            }
            status = polled.value("StackStatus");
            reason = polled.value("StackStatusReason");
            if (stackId.isEmpty()) {
                stackId = polled.value("StackId");
            }
            context.log("[cf] " + stackName + " is " + status);
            if (!status.endsWith("_IN_PROGRESS")) {
                break;
            }
        }

        boolean settled = status.endsWith("_COMPLETE") && !status.contains("ROLLBACK") && !status.contains("FAILED");
        AtomResult result = settled ? AtomResult.success()
                : AtomResult.error(ErrorType.THIRD_PART, 40008,
                        "the stack settled as " + status + (reason.isEmpty() ? "" : ": " + reason));
        return result
                .data("action", actionLabel)
                .data("status", status)
                .data("stackName", stackName)
                .data("stackId", stackId);
    }

    /** One Query-protocol call: form-encoded parameters, XML (or an error) back. */
    private Reply call(HttpClient client, AwsSigner signer, String endpoint, String host, String action,
                       Map<String, String> parameters, int timeoutSeconds) throws Exception {
        StringBuilder form = new StringBuilder("Action=").append(encode(action)).append("&Version=").append(VERSION);
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            form.append('&').append(encode(entry.getKey())).append('=').append(encode(entry.getValue()));
        }
        String body = form.toString();
        Map<String, String> signed = Map.of("content-type", "application/x-www-form-urlencoded; charset=utf-8");
        Map<String, String> headers = signer.headers("POST", "/", "", body, host, signed);

        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(endpoint + "/"))
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        headers.forEach(request::header);
        HttpResponse<String> response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
        return new Reply(response.statusCode(), response.body() == null ? "" : response.body());
    }

    private static Map<String, String> parseParameters(String value) {
        Map<String, String> parameters = new TreeMap<>();
        if (value.isBlank()) {
            return parameters;
        }
        try {
            Object parsed = com.jenkinschina.atom.sdk.Json.parse(value);
            if (parsed instanceof Map<?, ?> map) {
                map.forEach((key, entry) -> parameters.put(String.valueOf(key), String.valueOf(entry)));
                return parameters;
            }
        } catch (RuntimeException ignored) {
            // not JSON: fall through to key=value lines
        }
        for (String line : value.split("[,\\n]")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int split = trimmed.indexOf('=');
            if (split > 0) {
                parameters.put(trimmed.substring(0, split).trim(), trimmed.substring(split + 1).trim());
            }
        }
        return parameters;
    }

    private static String secret(AtomContext context, String name) {
        String value = context.getSecret(name);
        if (value == null || value.isBlank()) {
            value = context.getParam(name, "");
        }
        return value == null ? "" : value.trim();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String idOf(Reply reply) {
        return reply.value("StackId");
    }

    /** A CloudFormation answer: XML when it worked, an Error element when it did not. */
    private record Reply(int status, String body) {

        boolean ok() {
            return status >= 200 && status < 300;
        }

        String value(String tag) {
            Matcher matcher = Pattern.compile("<" + tag + ">([^<]*)</" + tag + ">").matcher(body);
            return matcher.find() ? unescape(matcher.group(1)) : "";
        }

        String errorCode() {
            return value("Code");
        }

        String message() {
            return value("Message");
        }

        String describe() {
            String code = errorCode();
            String message = message();
            if (!code.isEmpty() || !message.isEmpty()) {
                return (code.isEmpty() ? "HTTP " + status : code) + (message.isEmpty() ? "" : ": " + message);
            }
            String flat = body.replaceAll("\\s+", " ").trim();
            return "HTTP " + status + (flat.isEmpty() ? "" : " " + (flat.length() > 300 ? flat.substring(0, 300) + "…" : flat));
        }

        private static String unescape(String value) {
            return value.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
                    .replace("&quot;", "\"").replace("&apos;", "'");
        }
    }
}
