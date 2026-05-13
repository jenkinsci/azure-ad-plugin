package com.microsoft.jenkins.azuread.scribe;

import com.github.scribejava.core.httpclient.HttpClient;
import com.github.scribejava.core.httpclient.multipart.MultipartPayload;
import com.github.scribejava.core.model.OAuthAsyncRequestCallback;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;

import hudson.ProxyConfiguration;
import jenkins.model.Jenkins;
import jenkins.util.JenkinsJVM;
import okhttp3.Credentials;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.RequestBody;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.IOException;
import java.net.Proxy;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;


public class ScribeOkHttpClient implements HttpClient {

    private final OkHttpClient client;

    public ScribeOkHttpClient(String authorityHost) {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        this.client = addProxyToHttpClientIfRequired(builder, authorityHost).build();
    }

    @Override
    public <T> Future<T> executeAsync(String userAgent, Map<String, String> headers, Verb httpVerb, String completeUrl,
            byte[] bodyContents, OAuthAsyncRequestCallback<T> callback, OAuthRequest.ResponseConverter<T> converter) {
        return executeAsyncInternal(userAgent, headers, httpVerb, completeUrl, requestBody(headers, bodyContents),
                callback, converter);
    }

    @Override
    public <T> Future<T> executeAsync(String userAgent, Map<String, String> headers, Verb httpVerb, String completeUrl,
            MultipartPayload bodyContents, OAuthAsyncRequestCallback<T> callback,
            OAuthRequest.ResponseConverter<T> converter) {
        throw new UnsupportedOperationException("ScribeOkHttpClient does not support multipart payloads");
    }

    @Override
    public <T> Future<T> executeAsync(String userAgent, Map<String, String> headers, Verb httpVerb, String completeUrl,
            String bodyContents, OAuthAsyncRequestCallback<T> callback, OAuthRequest.ResponseConverter<T> converter) {
        return executeAsyncInternal(userAgent, headers, httpVerb, completeUrl, requestBody(headers, bodyContents),
                callback, converter);
    }

    @Override
    public <T> Future<T> executeAsync(String userAgent, Map<String, String> headers, Verb httpVerb, String completeUrl,
            File bodyContents, OAuthAsyncRequestCallback<T> callback, OAuthRequest.ResponseConverter<T> converter) {
        throw new UnsupportedOperationException("ScribeOkHttpClient does not support file payloads");
    }

    @Override
    public Response execute(String userAgent, Map<String, String> headers, Verb httpVerb, String completeUrl,
            byte[] bodyContents) throws IOException {
        return executeInternal(userAgent, headers, httpVerb, completeUrl, requestBody(headers, bodyContents));
    }

    @Override
    public Response execute(String userAgent, Map<String, String> headers, Verb httpVerb, String completeUrl,
            MultipartPayload bodyContents) {
        throw new UnsupportedOperationException("ScribeOkHttpClient does not support multipart payloads");
    }

    @Override
    public Response execute(String userAgent, Map<String, String> headers, Verb httpVerb, String completeUrl,
            String bodyContents) throws IOException {
        return executeInternal(userAgent, headers, httpVerb, completeUrl, requestBody(headers, bodyContents));
    }

    @Override
    public Response execute(String userAgent, Map<String, String> headers, Verb httpVerb, String completeUrl,
            File bodyContents) {
        throw new UnsupportedOperationException("ScribeOkHttpClient does not support file payloads");
    }

    @Override
    public void close() {
        client.dispatcher().executorService().shutdown();
        client.connectionPool().evictAll();
        okhttp3.Cache cache = client.cache();
        if (cache != null) {
            try {
                cache.close();
            } catch (IOException ignored) {
                // No local cache is configured, but close defensively if one is added later.
            }
        }
    }

    private <T> Future<T> executeAsyncInternal(String userAgent, Map<String, String> headers, Verb httpVerb,
            String completeUrl, RequestBody body, OAuthAsyncRequestCallback<T> callback,
            OAuthRequest.ResponseConverter<T> converter) {
        CompletableFuture<T> future = new CompletableFuture<>();
        try {
            Response response = executeInternal(userAgent, headers, httpVerb, completeUrl, body);
            @SuppressWarnings("unchecked")
            T result = converter == null ? (T) response : converter.convert(response);
            if (callback != null) {
                callback.onCompleted(result);
            }
            future.complete(result);
        } catch (IOException | RuntimeException e) {
            if (callback != null) {
                callback.onThrowable(e);
            }
            future.completeExceptionally(e);
        }
        return future;
    }

    private Response executeInternal(String userAgent, Map<String, String> headers, Verb httpVerb, String completeUrl,
            RequestBody requestBody) throws IOException {
        okhttp3.Request.Builder requestBuilder = new okhttp3.Request.Builder().url(completeUrl);
        if (StringUtils.isNotBlank(userAgent)) {
            requestBuilder.header("User-Agent", userAgent);
        }
        if (headers != null) {
            headers.forEach(requestBuilder::header);
        }

        if (httpVerb.isPermitBody()) {
            RequestBody body = requestBody;
            if (body == null && httpVerb.isRequiresBody()) {
                body = RequestBody.create(new byte[0]);
            }
            requestBuilder.method(httpVerb.name(), body);
        } else {
            requestBuilder.method(httpVerb.name(), null);
        }

        try (okhttp3.Response response = client.newCall(requestBuilder.build()).execute()) {
            okhttp3.ResponseBody responseBody = response.body();
            String body = responseBody != null ? responseBody.string() : null;
            return new Response(response.code(), response.message(), flattenHeaders(response.headers()), body);
        }
    }

    private static Map<String, String> flattenHeaders(Headers headers) {
        Map<String, String> flattenedHeaders = new LinkedHashMap<>();
        for (String name : headers.names()) {
            List<String> values = headers.values(name);
            flattenedHeaders.put(name, String.join(", ", values));
        }
        return flattenedHeaders;
    }

    private static RequestBody requestBody(Map<String, String> headers, String bodyContents) {
        if (bodyContents == null) {
            return null;
        }
        return RequestBody.create(bodyContents, mediaType(headers));
    }

    private static RequestBody requestBody(Map<String, String> headers, byte[] bodyContents) {
        if (bodyContents == null) {
            return null;
        }
        return RequestBody.create(bodyContents, mediaType(headers));
    }

    private static MediaType mediaType(Map<String, String> headers) {
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                if (HttpClient.CONTENT_TYPE.equalsIgnoreCase(entry.getKey())
                        && StringUtils.isNotBlank(entry.getValue())) {
                    return MediaType.parse(entry.getValue());
                }
            }
        }
        return MediaType.parse(HttpClient.DEFAULT_CONTENT_TYPE);
    }

    private static OkHttpClient.Builder addProxyToHttpClientIfRequired(OkHttpClient.Builder builder, String authorityHost) {
        if (JenkinsJVM.isJenkinsJVM()) {
            ProxyConfiguration proxyConfiguration = Jenkins.get().getProxy();
            if (proxyConfiguration != null && StringUtils.isNotBlank(proxyConfiguration.getName())) {

                String graphHost = URI.create(authorityHost).getHost();
                Proxy proxy = proxyConfiguration.createProxy(graphHost);

                builder = builder.proxy(proxy);
                if (StringUtils.isNotBlank(proxyConfiguration.getUserName())) {
                    builder = builder.proxyAuthenticator((route, response) -> {
                        String credential = Credentials.basic(
                                proxyConfiguration.getUserName(),
                                proxyConfiguration.getSecretPassword().getPlainText()
                        );
                        return response.request().newBuilder().header("Authorization", credential).build();
                    });
                }
            }
        }

        return builder;
    }    
}