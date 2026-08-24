package com.rkp.gateway.orchestrator;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.springframework.stereotype.Component;

import com.rkp.gateway.config.GatewayConfig;
import com.rkp.gateway.context.ContextRegistry;
import com.rkp.gateway.context.RequestContext;
import com.rkp.gateway.downstream.DownstreamManager;
import com.rkp.gateway.downstream.DownstreamResult;
import com.rkp.gateway.observability.GatewayLogger;
import com.rkp.gateway.observability.PerformanceLogger;
import com.rkp.gateway.observability.ReactorMdcBridge;
import com.rkp.gateway.rules.ExecutionRuleEngine;
import com.rkp.gateway.xml.XmlCodec;

import reactor.core.publisher.Mono;

@Component
public class TransactionOrchestrator {

    private static final Logger log =
            GatewayLogger.getLogger(
                    TransactionOrchestrator.class);

    private final ContextRegistry registry;
    private final XmlCodec codec;
    private final GatewayConfig config;
    private final ExecutionRuleEngine ruleEngine;
    private final DownstreamManager downstreamManager;
    private final PerformanceLogger performanceLogger;

    public TransactionOrchestrator(
            DownstreamManager downstreamManager,
            ContextRegistry registry,
            XmlCodec codec,
            GatewayConfig config,
            ExecutionRuleEngine ruleEngine,
            PerformanceLogger performanceLogger) {

        this.downstreamManager = downstreamManager;
        this.registry = registry;
        this.codec = codec;
        this.config = config;
        this.ruleEngine = ruleEngine;
        this.performanceLogger = performanceLogger;
    }

    public Mono<String> process(
            RequestContext context) {

        /*
         * IMPORTANT
         * ---------------------------------------------------------
         *
         * Do NOT create a LogContext here.
         *
         * GatewayHandler already created the single transaction
         * LogContext and placed it into Reactor Context.
         *
         * Every operator below consumes that same context.
         */
        return Mono.deferContextual(reactorContext -> {

            /*
             * Restore the propagated transaction context for the
             * synchronous code executed in this callback.
             */
            ReactorMdcBridge.apply(
                    reactorContext);

            GatewayLogger.info(
                    log,
                    "TXN orchestration started");

            /*
             * -----------------------------------------------------
             * Execute downstream systems
             * -----------------------------------------------------
             */

            return downstreamManager
                    .execute(context)

                    /*
                     * Transaction-level timeout.
                     *
                     * Keep the existing configuration for now.
                     */
                    .timeout(
                            Duration.ofMillis(
                                    config.getDownstream()
                                            .getTransactionTimeoutMs()))

                    /*
                     * -------------------------------------------------
                     * Downstream aggregation + rule evaluation
                     * -------------------------------------------------
                     */

                    .map(results -> {

                        /*
                         * Restore the SAME transaction context.
                         */
                        ReactorMdcBridge.apply(
                                reactorContext);

                        GatewayLogger.debug(
                                log,
                                "Downstream completed systems={} gatewayElapsed={}ms",
                                results.keySet(),
                                context.gatewayLatencyMillis());

                        Map<String, String> responseCodes =
                                new LinkedHashMap<>();

                        for (Map.Entry<String, DownstreamResult> entry :
                                results.entrySet()) {

                            String system =
                                    entry.getKey();

                            DownstreamResult result =
                                    entry.getValue();

                            responseCodes.put(
                                    system,
                                    result.responseCode());

                            GatewayLogger.debug(
                                    log,
                                    "Downstream {} rc={} latency={}ms",
                                    system,
                                    result.responseCode(),
                                    context.downstream(system)
                                            .latencyMillis());
                        }

                        /*
                         * -------------------------------------------------
                         * Rule engine
                         * -------------------------------------------------
                         */

                        AggregatedResult aggregatedResult =
                                ruleEngine.evaluate(
                                        responseCodes);

                        GatewayLogger.info(
                                log,
                                "Rule engine selected rc={} action={} settlement={}",
                                aggregatedResult.responseCode(),
                                aggregatedResult.action(),
                                aggregatedResult.settlement());

                        /*
                         * -------------------------------------------------
                         * Build gateway response
                         * -------------------------------------------------
                         */

                        Map<String, String> response =
                                new LinkedHashMap<>();

                        response.put(
                                "rec",
                                "TXN_RESP");

                        response.put(
                                "msgId",
                                context.getClientMsgId());

                        /*
                         * Canonical transaction correlation ID.
                         */
                        response.put(
                                "correlationId",
                                String.valueOf(
                                        context.getCorrelationId()));

                        response.put(
                                "respCode",
                                aggregatedResult.responseCode());

                        response.put(
                                "respMsg",
                                aggregatedResult.message());

                        response.put(
                                "action",
                                aggregatedResult.action());

                        response.put(
                                "hostCode",
                                aggregatedResult.hostCode());

                        response.put(
                                "settlement",
                                aggregatedResult.settlement());

                        /*
                         * Mark transaction complete before measuring
                         * final gateway latency.
                         */
                        context.markGatewayCompleted();

                        long latency =
                                context.gatewayLatencyMillis();

                        performanceLogger.transactionCompleted(
                                latency);

                        GatewayLogger.info(
                                log,
                                "TXN completed {}",
                                context.summary());

                        return codec.build(response);
                    })

                    /*
                     * -------------------------------------------------
                     * Transaction failure / timeout
                     * -------------------------------------------------
                     */

                    .onErrorResume(ex -> {

                        /*
                         * Restore SAME transaction context.
                         */
                        ReactorMdcBridge.apply(
                                reactorContext);

                        context.markGatewayCompleted();

                        long latency =
                                context.gatewayLatencyMillis();

                        performanceLogger.transactionTimedOut(
                                latency);

                        GatewayLogger.warn(
                                log,
                                "TXN timeout after {}ms type={} message={}",
                                latency,
                                ex.getClass()
                                        .getSimpleName(),
                                ex.getMessage());

                        Map<String, String> response =
                                new LinkedHashMap<>();

                        response.put(
                                "rec",
                                "TXN_RESP");

                        response.put(
                                "msgId",
                                context.getClientMsgId());

                        response.put(
                                "correlationId",
                                String.valueOf(
                                        context.getCorrelationId()));

                        response.put(
                                "respCode",
                                "91");

                        response.put(
                                "respMsg",
                                "TIMEOUT");

                        return Mono.just(
                                codec.build(response));
                    })

                    /*
                     * -------------------------------------------------
                     * Context registry completion
                     * -------------------------------------------------
                     */

                    .doOnSuccess(xml -> {

                        ReactorMdcBridge.apply(
                                reactorContext);

                        registry.complete(
                                context.getCorrelationId(),
                                xml);

                        GatewayLogger.debug(
                                log,
                                "Context completed correlationId={}",
                                context.getCorrelationId());
                    })

                    /*
                     * -------------------------------------------------
                     * Unexpected pipeline failure
                     * -------------------------------------------------
                     */

                    .doOnError(ex -> {

                        ReactorMdcBridge.apply(
                                reactorContext);

                        performanceLogger.transactionFailed();

                        registry.fail(
                                context.getCorrelationId(),
                                ex);

                        GatewayLogger.error(
                                log,
                                "TXN failed type={} message={}",
                                ex.getClass()
                                        .getSimpleName(),
                                ex.getMessage());
                    });
        });
    }
}