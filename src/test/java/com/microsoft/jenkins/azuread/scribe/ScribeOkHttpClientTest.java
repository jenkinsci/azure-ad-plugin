package com.microsoft.jenkins.azuread.scribe;

import com.github.scribejava.core.httpclient.HttpClient;
import com.github.scribejava.core.httpclient.multipart.MultipartPayload;
import com.github.scribejava.core.model.OAuthAsyncRequestCallback;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Locale;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScribeOkHttpClientTest {

    private final List<ScribeOkHttpClient> clients = new ArrayList<>();
    private HttpServer server;

    @AfterEach
    void tearDown() {
        for (ScribeOkHttpClient client : clients) {
            client.close();
        }
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void executeUsesHeadersRequestBodyAndResponse() throws Exception {
        CapturedExchange capturedExchange = new CapturedExchange();
        startServer(capturedExchange, exchange -> {
            exchange.getResponseHeaders().add("X-Test", "one");
            exchange.getResponseHeaders().add("X-Test", "two");
            writeResponse(exchange, 201, "created");
        });

        ScribeOkHttpClient client = newClient();
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(HttpClient.CONTENT_TYPE, "application/json");
        headers.put("X-Custom", "value");

        Response response = client.execute(
                "agent/1.0",
                headers,
                Verb.POST,
                serverUrl("/string-body"),
                "{\"hello\":true}");

        assertEquals(201, response.getCode());
        assertEquals("created", response.getBody());
        assertEquals("one, two", responseHeader(response, "X-Test"));

        assertEquals("POST", capturedExchange.method);
        assertEquals("agent/1.0", capturedExchange.header("User-Agent"));
        assertEquals("application/json; charset=utf-8", capturedExchange.header("Content-Type"));
        assertEquals("value", capturedExchange.header("X-Custom"));
        assertEquals("{\"hello\":true}", capturedExchange.bodyAsString());
    }

    @Test
    void executeWithByteArrayUsesExplicitContentType() throws Exception {
        CapturedExchange capturedExchange = new CapturedExchange();
        startServer(capturedExchange, exchange -> writeResponse(exchange, 200, "bytes"));

        ScribeOkHttpClient client = newClient();
        Map<String, String> headers = Map.of(HttpClient.CONTENT_TYPE, "application/octet-stream");
        byte[] payload = new byte[] {1, 2, 3, 4};

        Response response = client.execute("agent/2.0", headers, Verb.PUT, serverUrl("/bytes"), payload);

        assertEquals(200, response.getCode());
        assertEquals("bytes", response.getBody());
        assertArrayEquals(payload, capturedExchange.body);
        assertEquals("application/octet-stream", capturedExchange.header("Content-Type"));
    }

    @Test
    void executeUsesDefaultContentTypeWhenHeadersAreMissing() throws Exception {
        CapturedExchange capturedExchange = new CapturedExchange();
        startServer(capturedExchange, exchange -> writeResponse(exchange, 200, "default-type"));

        ScribeOkHttpClient client = newClient();

        Response response = client.execute("agent/3.0", null, Verb.POST, serverUrl("/default-type"), "plain-text");

        assertEquals(200, response.getCode());
        assertEquals("default-type", response.getBody());
        assertEquals("POST", capturedExchange.method);
        assertEquals("application/x-www-form-urlencoded; charset=utf-8", capturedExchange.header("Content-Type"));
        assertEquals("plain-text", capturedExchange.bodyAsString());
    }

    @Test
    void executeUsesEmptyBodyForRequiredVerbWhenPayloadIsMissing() throws Exception {
        CapturedExchange capturedExchange = new CapturedExchange();
        startServer(capturedExchange, exchange -> writeResponse(exchange, 202, "accepted"));

        ScribeOkHttpClient client = newClient();

        Response response = client.execute("agent/3.0", null, Verb.POST, serverUrl("/empty"), (String) null);

        assertEquals(202, response.getCode());
        assertEquals("accepted", response.getBody());
        assertEquals("POST", capturedExchange.method);
        assertArrayEquals(new byte[0], capturedExchange.body);
        assertNull(capturedExchange.header("Content-Type"));
    }

    @Test
    void executeAsyncReturnsConvertedResponseAndInvokesCompletionCallback() throws Exception {
        CapturedExchange capturedExchange = new CapturedExchange();
        startServer(capturedExchange, exchange -> writeResponse(exchange, 200, "async-ok"));

        ScribeOkHttpClient client = newClient();
        TrackingCallback callback = new TrackingCallback();
        OAuthRequest.ResponseConverter<String> converter = response -> response.getCode() + ":" + response.getBody();

        Future<String> future = client.executeAsync(
                "agent/4.0",
                Map.of("X-Async", "true"),
                Verb.POST,
                serverUrl("/async"),
                "payload",
                callback,
                converter);

        assertEquals("200:async-ok", future.get());
        assertEquals("200:async-ok", callback.completed);
        assertNull(callback.throwable);
        assertEquals("payload", capturedExchange.bodyAsString());
        assertEquals("true", capturedExchange.header("X-Async"));
    }

    @Test
    void executeAsyncCompletesExceptionallyAndInvokesThrowableCallback() {
        ScribeOkHttpClient client = newClient();
        TrackingCallback callback = new TrackingCallback();

        Future<String> future = client.executeAsync(
                "agent/5.0",
                Map.of(),
                Verb.GET,
                "http://127.0.0.1:" + unusedPort() + "/unreachable",
                "payload",
                callback,
                Response::getBody);

            ExecutionException exception = assertThrows(ExecutionException.class, future::get);
            assertTrue(exception.getCause() instanceof IOException);
        assertNull(callback.completed);
        assertTrue(callback.throwable instanceof IOException);
    }

    @Test
    void unsupportedPayloadTypesThrow() {
        ScribeOkHttpClient client = newClient();

        assertThrows(
                UnsupportedOperationException.class,
                () -> client.executeAsync("ua", Map.of(), Verb.POST, "http://localhost", (MultipartPayload) null, null, null));
        assertThrows(
                UnsupportedOperationException.class,
                () -> client.executeAsync("ua", Map.of(), Verb.POST, "http://localhost", new File("test.txt"), null, null));
        assertThrows(
                UnsupportedOperationException.class,
                () -> client.execute("ua", Map.of(), Verb.POST, "http://localhost", (MultipartPayload) null));
        assertThrows(
                UnsupportedOperationException.class,
                () -> client.execute("ua", Map.of(), Verb.POST, "http://localhost", new File("test.txt")));
    }

    @Test
    void closeIsIdempotentWithoutCache() {
        ScribeOkHttpClient client = newClient();

        client.close();
        client.close();
    }

    private ScribeOkHttpClient newClient() {
        ScribeOkHttpClient client = new ScribeOkHttpClient("https://login.microsoftonline.com/common");
        clients.add(client);
        return client;
    }

    private void startServer(CapturedExchange capturedExchange, HttpHandler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/", exchange -> {
            capturedExchange.capture(exchange);
            handler.handle(exchange);
        });
        server.start();
    }

    private String serverUrl(String path) {
        return "http://127.0.0.1:" + server.getAddress().getPort() + path;
    }

    private static void writeResponse(HttpExchange exchange, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(bytes);
        }
    }

    private static int unusedPort() {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            return serverSocket.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException("Unable to allocate a test port", e);
        }
    }

    private static String responseHeader(Response response, String name) {
        Optional<Map.Entry<String, String>> header = response.getHeaders().entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(name))
                .findFirst();
        return header.map(Map.Entry::getValue).orElse(null);
    }

    private static final class TrackingCallback implements OAuthAsyncRequestCallback<String> {

        private String completed;
        private Throwable throwable;

        @Override
        public void onCompleted(String response) {
            this.completed = response;
        }

        @Override
        public void onThrowable(Throwable throwable) {
            this.throwable = throwable;
        }
    }

    private static final class CapturedExchange {

        private String method;
        private Map<String, String> headers;
        private byte[] body;

        private void capture(HttpExchange exchange) throws IOException {
            this.method = exchange.getRequestMethod();
            this.headers = new LinkedHashMap<>();
            exchange.getRequestHeaders().forEach(this::putHeader);
            this.body = readAllBytes(exchange.getRequestBody());
        }

        private String bodyAsString() {
            return new String(body, StandardCharsets.UTF_8);
        }

        private String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }

        private static byte[] readAllBytes(InputStream inputStream) throws IOException {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, read);
            }
            return outputStream.toByteArray();
        }

        private void putHeader(String key, List<String> value) {
            headers.put(key.toLowerCase(Locale.ROOT), String.join(", ", value));
        }
    }
}