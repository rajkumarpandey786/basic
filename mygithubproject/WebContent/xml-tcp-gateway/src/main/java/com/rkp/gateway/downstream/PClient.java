package com.rkp.gateway.downstream;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.rkp.gateway.config.GatewayConfig;
import com.rkp.gateway.context.RequestContext;
import com.rkp.gateway.xml.XmlCodec;

import io.github.resilience4j.bulkhead.Bulkhead;
import io.github.resilience4j.bulkhead.BulkheadRegistry;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.reactor.bulkhead.operator.BulkheadOperator;
import io.github.resilience4j.reactor.circuitbreaker.operator.CircuitBreakerOperator;
import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

@Component
public class PClient {

    private final WebClient client;
    private final CircuitBreaker circuitBreaker;
    private final Bulkhead bulkhead;
    private final XmlCodec codec;

    public PClient(GatewayConfig config,
                   XmlCodec codec,
                   CircuitBreakerRegistry cbRegistry,
                   BulkheadRegistry bhRegistry) {

        this.codec = codec;

        GatewayConfig.Downstream.SystemConfig ds =
                config.getDownstream().getSystems().get("P");

        ConnectionProvider provider =
                ConnectionProvider.builder("p-pool")
                        .maxConnections(ds.getMaxConnections())
                        .pendingAcquireMaxCount(5000)
                        .pendingAcquireTimeout(Duration.ofSeconds(2))
                        .maxIdleTime(Duration.ofSeconds(30))
                        .lifo()
                        .build();

        HttpClient httpClient = HttpClient.create(provider)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS,
                        ds.getConnectTimeoutMs())
                .responseTimeout(Duration.ofMillis(
                        ds.getResponseTimeoutMs()))
                .doOnConnected(conn -> conn
                        .addHandlerLast(new ReadTimeoutHandler(
                                ds.getResponseTimeoutMs(),
                                TimeUnit.MILLISECONDS))
                        .addHandlerLast(new WriteTimeoutHandler(
                                ds.getResponseTimeoutMs(),
                                TimeUnit.MILLISECONDS)));

        this.client = WebClient.builder()
                .baseUrl(ds.getUrl())
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();

        this.circuitBreaker = cbRegistry.circuitBreaker("P");
        this.bulkhead = bhRegistry.bulkhead("P");
    }

    public Mono<Map<String, String>> call(RequestContext context) {

        context.setDownstreamRequest2(context.getRequestXml());

        return client.post()
                .uri("/api/process")
                .contentType(MediaType.APPLICATION_XML)
                .bodyValue(context.getRequestXml())
                .retrieve()
                .bodyToMono(String.class)

                .transformDeferred(BulkheadOperator.of(bulkhead))
                .transformDeferred(CircuitBreakerOperator.of(circuitBreaker))

                .map(body -> {

                    context.setResponse2(body);

                    Map<String, String> parsed = codec.parse(body);

                    return Map.of(
                            "system", "P",
                            "responseCode",
                            parsed.getOrDefault("respCode", "96"),
                            "message", body);
                });
    }
}
