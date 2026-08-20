package com.rkp.gateway.downstream;

import org.slf4j.Logger;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rkp.gateway.config.GatewayConfig;
import com.rkp.gateway.config.WebClientFactory;
import com.rkp.gateway.context.RequestContext;
import com.rkp.gateway.observability.GatewayLogger;
import com.rkp.gateway.observability.MaskingUtil;
import com.rkp.gateway.observability.ReactorMdcBridge;

import reactor.core.publisher.Mono;

@Component
public class PClient implements DownstreamClient {

    private static final Logger log =
            GatewayLogger.getLogger(PClient.class);

    private static final ObjectMapper MAPPER =
            new ObjectMapper();

    /*
     * Dedicated WebClient for downstream P.
     *
     * WebClientFactory creates the P-specific connection pool
     * and HTTP configuration from:
     *
     * gateway.downstream.systems.P
     */
    private final WebClient webClient;

    private final GatewayConfig config;

    private final MaskingUtil maskingUtil;

    public PClient(WebClientFactory webClientFactory,
                   GatewayConfig config,
                   MaskingUtil maskingUtil) {

        /*
         * P gets its own WebClient and therefore its own
         * ConnectionProvider.
         */
        this.webClient =
                webClientFactory.create("P");

        this.config = config;
        this.maskingUtil = maskingUtil;
    }

    @Override
    public String systemName() {
        return "P";
    }

    @Override
    public Mono<DownstreamResult> call(
            RequestContext context) {

        final String system = systemName();

        /*
         * IMPORTANT
         * ---------------------------------------------------------
         *
         * Do NOT use LogContextHolder here.
         *
         * GatewayHandler creates the LogContext once for the
         * transaction.
         *
         * Micrometer Context Propagation carries that same
         * context through the Reactor pipeline.
         *
         * Reactor Context is the source of truth.
         */
        return Mono.deferContextual(reactorContext -> {

            /*
             * Restore the propagated Reactor context into
             * ThreadLocal/MDC for the synchronous code executing
             * inside this callback.
             */
            ReactorMdcBridge.apply(reactorContext);

            GatewayLogger.info(
                    log,
                    "Calling downstream {}",
                    system);

            GatewayLogger.debug(
                    log,
                    "Downstream {} request preparation started",
                    system);

            /*
             * -----------------------------------------------------
             * Build P downstream request
             * -----------------------------------------------------
             */

            PRequest request = new PRequest();

            request.setMsgId(
                    context.getClientMsgId());

            request.setTerminalId(
                    context.getTerminalId());

            request.setAmount(
                    context.getRequestData()
                            .getOrDefault(
                                    "amount",
                                    "0"));

            /*
             * -----------------------------------------------------
             * Store masked request payload
             * -----------------------------------------------------
             *
             * Never log the original JSON.
             */
            try {

                String requestJson =
                        MAPPER.writeValueAsString(request);

                String maskedRequest =
                        maskingUtil.maskJson(requestJson);

                context.downstream(system)
                        .setRequestPayload(
                                maskedRequest);

                GatewayLogger.debug(
                        log,
                        "Downstream {} request prepared",
                        system);

            } catch (Exception ex) {

                GatewayLogger.debug(
                        log,
                        "Unable to serialize downstream {} request",
                        system);
            }

            /*
             * -----------------------------------------------------
             * Resolve P configuration
             * -----------------------------------------------------
             */

            GatewayConfig.Downstream.SystemConfig systemConfig =
                    config.getDownstream()
                            .getSystems()
                            .get(system);

            if (systemConfig == null) {

                GatewayLogger.error(
                        log,
                        "No configuration found for downstream {}",
                        system);

                return Mono.just(
                        DownstreamResult.timeout(
                                system,
                                context.downstream(system)
                                        .latencyMillis()));
            }

            /*
             * -----------------------------------------------------
             * Execute P HTTP request
             * -----------------------------------------------------
             *
             * IMPORTANT:
             *
             * There is intentionally NO local .timeout(...)
             * here.
             *
             * P's connection and response timeout are configured
             * in the dedicated P WebClient created by
             * WebClientFactory.
             *
             * Example:
             *
             * gateway:
             *   downstream:
             *     systems:
             *       P:
             *         connectTimeoutMs: 500
             *         responseTimeoutMs: 700
             *         keepAlive: false
             */

            return webClient.post()

                    .uri(
                            systemConfig.getUrl()
                                    + "/api/process")

                    .contentType(
                            MediaType.APPLICATION_JSON)

                    .bodyValue(request)

                    .retrieve()

                    .bodyToMono(PResponse.class)

                    /*
                     * -------------------------------------------------
                     * SUCCESS
                     * -------------------------------------------------
                     */
                    .map(response -> {

                        /*
                         * Reactor may execute this callback on a
                         * different thread.
                         *
                         * Restore the same transaction context
                         * before logging.
                         */
                        ReactorMdcBridge.apply(
                                reactorContext);

                        try {

                            String responseJson =
                                    MAPPER.writeValueAsString(
                                            response);

                            String maskedResponse =
                                    maskingUtil.maskJson(
                                            responseJson);

                            context.downstream(system)
                                    .setResponsePayload(
                                            maskedResponse);

                        } catch (Exception ex) {

                            GatewayLogger.debug(
                                    log,
                                    "Unable to serialize downstream {} response",
                                    system);
                        }

                        GatewayLogger.info(
                                log,
                                "Downstream {} response rc={}",
                                system,
                                response.getResponseCode());

                        GatewayLogger.debug(
                                log,
                                "Downstream {} completed latencyMs={}",
                                system,
                                context.downstream(system)
                                        .latencyMillis());

                        return DownstreamResult.success(
                                system,
                                response.getResponseCode(),
                                response.getResponseMessage(),
                                context.downstream(system)
                                        .latencyMillis());
                    })

                    /*
                     * -------------------------------------------------
                     * FAILURE / TIMEOUT
                     * -------------------------------------------------
                     */
                    .onErrorResume(ex -> {

                        /*
                         * This callback can execute on a different
                         * Reactor thread.
                         *
                         * Restore the SAME transaction context.
                         */
                        ReactorMdcBridge.apply(
                                reactorContext);

                        String reason =
                                ex.getMessage();

                        if (reason == null ||
                                reason.isBlank()) {

                            reason =
                                    ex.getClass()
                                            .getSimpleName();
                        }

                        GatewayLogger.warn(
                                log,
                                "Downstream {} timeout/failure type={} message={}",
                                system,
                                ex.getClass()
                                        .getSimpleName(),
                                reason);

                        GatewayLogger.debug(
                                log,
                                "Downstream {} failed latencyMs={}",
                                system,
                                context.downstream(system)
                                        .latencyMillis());

                        return Mono.just(
                                DownstreamResult.timeout(
                                        system,
                                        context.downstream(system)
                                                .latencyMillis()));
                    });
        });
    }
}