package com.rkp.gateway.config;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.rkp.gateway.observability.GatewayLogger;

import io.netty.channel.ChannelOption;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

@Component
public class WebClientFactory {

    private static final Logger log =
            GatewayLogger.getLogger(WebClientFactory.class);

    private final GatewayConfig gatewayConfig;

    /*
     * One reusable WebClient per downstream system.
     *
     * T -> T WebClient -> T ConnectionProvider
     * P -> P WebClient -> P ConnectionProvider
     */
    private final Map<String, WebClient> clients =
            new ConcurrentHashMap<>();

    public WebClientFactory(GatewayConfig gatewayConfig) {
        this.gatewayConfig = gatewayConfig;
    }

    public WebClient create(String system) {

        return clients.computeIfAbsent(
                system,
                this::createWebClient);
    }

    private WebClient createWebClient(String system) {

        GatewayConfig.Downstream.SystemConfig cfg =
                gatewayConfig.getDownstream()
                        .getSystems()
                        .get(system);

        if (cfg == null) {
            throw new IllegalStateException(
                    "No downstream configuration found for system: "
                            + system);
        }

        String poolName =
                "gateway-" +
                system.toLowerCase() +
                "-pool";

        /*
         * Dedicated connection pool for this downstream.
         */
        ConnectionProvider provider =
                ConnectionProvider.builder(poolName)

                        .maxConnections(
                                cfg.getMaxConnections())

                        .pendingAcquireMaxCount(
                                cfg.getPendingAcquireMaxCount())

                        .pendingAcquireTimeout(
                                Duration.ofMillis(
                                        cfg.getPendingAcquireTimeoutMs()))

                        .maxIdleTime(
                                Duration.ofMillis(
                                        cfg.getMaxIdleTimeMs()))

                        .maxLifeTime(
                                Duration.ofMillis(
                                        cfg.getMaxLifeTimeMs()))

                        .build();

        /*
         * Dedicated HTTP client for this downstream.
         */
        HttpClient httpClient =
                HttpClient.create(provider)

                        /*
                         * TCP connection establishment timeout.
                         */
                        .option(
                                ChannelOption.CONNECT_TIMEOUT_MILLIS,
                                cfg.getConnectTimeoutMs())

                        /*
                         * Downstream-specific HTTP response timeout.
                         */
                        .responseTimeout(
                                Duration.ofMillis(
                                        cfg.getResponseTimeoutMs()))

                        /*
                         * Downstream-specific HTTP keep-alive.
                         *
                         * true:
                         *   persistent connections can be reused.
                         *
                         * false:
                         *   persistent HTTP connection reuse is disabled.
                         */
                        .keepAlive(
                                cfg.isKeepAlive());

        GatewayLogger.info(
                log,
                "WebClient initialized system={} " +
                "pool={} " +
                "maxConnections={} " +
                "pendingAcquireMax={} " +
                "pendingAcquireTimeout={}ms " +
                "connectTimeout={}ms " +
                "responseTimeout={}ms " +
                "idleTime={}ms " +
                "lifeTime={}ms " +
                "keepAlive={}",

                system,
                poolName,
                cfg.getMaxConnections(),
                cfg.getPendingAcquireMaxCount(),
                cfg.getPendingAcquireTimeoutMs(),
                cfg.getConnectTimeoutMs(),
                cfg.getResponseTimeoutMs(),
                cfg.getMaxIdleTimeMs(),
                cfg.getMaxLifeTimeMs(),
                cfg.isKeepAlive());

        return WebClient.builder()
                .clientConnector(
                        new ReactorClientHttpConnector(
                                httpClient))
                .build();
    }
}