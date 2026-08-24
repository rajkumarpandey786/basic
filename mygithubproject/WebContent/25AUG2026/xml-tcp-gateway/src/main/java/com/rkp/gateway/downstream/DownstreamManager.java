package com.rkp.gateway.downstream;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.springframework.stereotype.Component;

import com.rkp.gateway.config.GatewayConfig;
import com.rkp.gateway.context.RequestContext;
import com.rkp.gateway.observability.GatewayLogger;
import com.rkp.gateway.observability.ReactorMdcBridge;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class DownstreamManager {

    private static final Logger log =
            GatewayLogger.getLogger(DownstreamManager.class);

    private final GatewayConfig config;

    /*
     * Generic downstream registry.
     *
     * No hard-coded T/P dependency here.
     *
     * The active systems are controlled entirely through
     * configuration.
     */
    private final Map<String, DownstreamClient> clients =
            new LinkedHashMap<>();

    public DownstreamManager(
            GatewayConfig config,
            List<DownstreamClient> downstreamClients) {

        this.config = config;

        for (DownstreamClient client : downstreamClients) {

            clients.put(
                    client.systemName(),
                    client);
        }

        GatewayLogger.info(
                log,
                "DownstreamManager initialized clients={}",
                clients.keySet());
    }

    public Mono<Map<String, DownstreamResult>> execute(
            RequestContext context) {

        /*
         * Do not create a LogContext here.
         *
         * GatewayHandler created the transaction LogContext.
         *
         * Micrometer/Reactor Context propagates that same context
         * into this method and subsequently into the downstream
         * clients.
         */
        return Mono.deferContextual(reactorContext -> {

            /*
             * Restore the propagated transaction context for the
             * synchronous code executed in this callback.
             */
            ReactorMdcBridge.apply(
                    reactorContext);

            List<Mono<DownstreamResult>> calls =
                    new ArrayList<>();

            /*
             * Active downstream systems come entirely from
             * configuration.
             *
             * Example:
             *
             * active:
             *   - T
             *   - P
             *
             * or:
             *
             * active:
             *   - X
             *
             * or:
             *
             * active:
             *   - A
             *
             * No Java code changes are required.
             */
            for (String system :
                    config.getDownstream()
                            .getActive()) {

                DownstreamClient client =
                        clients.get(system);

                /*
                 * -------------------------------------------------
                 * Missing client implementation
                 * -------------------------------------------------
                 */

                if (client == null) {

                    GatewayLogger.warn(
                            log,
                            "Configured downstream {} has no client implementation",
                            system);

                    continue;
                }

                /*
                 * -------------------------------------------------
                 * Schedule downstream
                 * -------------------------------------------------
                 */

                GatewayLogger.info(
                        log,
                        "Scheduling downstream {}",
                        system);

                /*
                 * -------------------------------------------------
                 * Build downstream pipeline
                 * -------------------------------------------------
                 *
                 * deferContextual ensures that the propagated
                 * transaction context is available when this
                 * downstream pipeline is subscribed.
                 */
                Mono<DownstreamResult> call =

                        Mono.deferContextual(
                                downstreamContext -> {

                            /*
                             * Restore the SAME LogContext.
                             */
                            ReactorMdcBridge.apply(
                                    downstreamContext);

                            /*
                             * Start latency measurement at actual
                             * subscription/execution time.
                             */
                            context.downstream(system)
                                    .markStart();

                            GatewayLogger.debug(
                                    log,
                                    "Downstream {} execution started",
                                    system);

                            return client.call(context)

                                    /*
                                     * -------------------------------------------------
                                     * SUCCESS
                                     * -------------------------------------------------
                                     */

                                    .doOnSuccess(result -> {

                                        ReactorMdcBridge.apply(
                                                downstreamContext);

                                        context.downstream(system)
                                                .markEnd();

                                        GatewayLogger.info(
                                                log,
                                                "Downstream {} completed rc={} latency={}ms",
                                                system,
                                                result.responseCode(),
                                                context.downstream(system)
                                                        .latencyMillis());
                                    })

                                    /*
                                     * -------------------------------------------------
                                     * ERROR
                                     * -------------------------------------------------
                                     */

                                    .doOnError(ex -> {

                                        ReactorMdcBridge.apply(
                                                downstreamContext);

                                        context.downstream(system)
                                                .markEnd();

                                        GatewayLogger.error(
                                                log,
                                                "Downstream {} failed type={} message={} latency={}ms",
                                                system,
                                                ex.getClass()
                                                        .getSimpleName(),
                                                ex.getMessage(),
                                                context.downstream(system)
                                                        .latencyMillis());
                                    });
                        });

                calls.add(call);
            }

            /*
             * -----------------------------------------------------
             * Execute all configured downstream systems
             * -----------------------------------------------------
             *
             * Flux.merge subscribes to all downstream Monos and
             * therefore T/P/X/Y/etc. can execute concurrently.
             */
            GatewayLogger.info(
                    log,
                    "Executing {} downstream systems {}",
                    calls.size(),
                    config.getDownstream()
                            .getActive());

            return Flux.merge(calls)

                    .collectMap(
                            DownstreamResult::system,
                            result -> result)

                    /*
                     * -------------------------------------------------
                     * ALL DOWNSTREAMS COMPLETED
                     * -------------------------------------------------
                     */

                    .doOnSuccess(results -> {

                        ReactorMdcBridge.apply(
                                reactorContext);

                        GatewayLogger.info(
                                log,
                                "All downstream systems completed count={}",
                                results.size());
                    });
        });
    }
}