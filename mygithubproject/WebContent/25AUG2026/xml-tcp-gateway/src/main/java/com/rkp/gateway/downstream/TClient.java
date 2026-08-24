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
public class TClient implements DownstreamClient {

    private static final Logger log =
            GatewayLogger.getLogger(TClient.class);

    private static final ObjectMapper MAPPER =
            new ObjectMapper();

    private final WebClient webClient;
    private final GatewayConfig config;
    private final MaskingUtil maskingUtil;

    public TClient(WebClientFactory webClientFactory,
                   GatewayConfig config,
                   MaskingUtil maskingUtil) {

        /*
         * T has its own WebClient and therefore its own
         * connection pool.
         *
         * The WebClientFactory creates it only once and
         * subsequent calls reuse the same WebClient.
         */
        this.webClient =
                webClientFactory.create("T");

        this.config = config;
        this.maskingUtil = maskingUtil;
    }

    @Override
    public String systemName() {
        return "T";
    }

    @Override
    public Mono<DownstreamResult> call(
            RequestContext context) {

        final String system = systemName();

        /*
         * ---------------------------------------------------------
         * REACTOR CONTEXT
         * ---------------------------------------------------------
         *
         * Do not create or manually manage LogContext here.
         *
         * GatewayHandler creates the transaction LogContext.
         *
         * Micrometer Context Propagation + Reactor Context
         * carries that context to this client.
         */
        return Mono.deferContextual(reactorContext -> {

            /*
             * Restore Reactor/Micrometer context into MDC
             * for the synchronous code executed below.
             */
            ReactorMdcBridge.apply(reactorContext);

            GatewayLogger.info(
                    log,
                    "Calling downstream {}",
                    system);

            /*
             * -----------------------------------------------------
             * BUILD REQUEST
             * -----------------------------------------------------
             */

            TRequest request =
                    new TRequest();

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
             * MASKED REQUEST OBSERVABILITY
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
             * DOWNSTREAM CONFIGURATION
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
             * HTTP CALL
             * -----------------------------------------------------
             *
             * IMPORTANT:
             *
             * No .timeout() here.
             *
             * The T-specific response timeout is configured
             * inside WebClientFactory using:
             *
             * gateway.downstream.systems.T.responseTimeoutMs
             */
            return webClient.post()

                    .uri(
                            systemConfig.getUrl()
                                    + "/api/process")

                    .contentType(
                            MediaType.APPLICATION_JSON)

                    .bodyValue(request)

                    .retrieve()

                    .bodyToMono(TResponse.class)

                    /*
                     * -------------------------------------------------
                     * SUCCESS
                     * -------------------------------------------------
                     */
                    .map(response -> {

                        /*
                         * This callback may execute on another
                         * Reactor thread.
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
                         * The error callback can execute on another
                         * Reactor thread.
                         *
                         * Restore the transaction context.
                         */
                        ReactorMdcBridge.apply(
                                reactorContext);

                        GatewayLogger.warn(
                                log,
                                "Downstream {} timeout/failure type={} message={}",
                                system,
                                ex.getClass()
                                        .getSimpleName(),
                                ex.getMessage());

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