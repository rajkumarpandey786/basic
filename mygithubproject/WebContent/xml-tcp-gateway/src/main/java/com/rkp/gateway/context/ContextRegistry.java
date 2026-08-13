package com.rkp.gateway.context;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.stereotype.Component;

import com.rkp.gateway.config.GatewayConfig;

@Component
public class ContextRegistry {

    private final GatewayConfig config;

    private final AtomicLong correlationGenerator = new AtomicLong();

    private final ConcurrentHashMap<Long, RequestContext> contexts =
            new ConcurrentHashMap<>();

    public ContextRegistry(GatewayConfig config) {
        this.config = config;
    }

    public RequestContext create(String sessionId,
                                 String clientMsgId,
                                 String requestXml) {

        if (contexts.size() >=
                config.getDownstream().getMaxInflightTransactions()) {

            throw new IllegalStateException(
                    "MAX_INFLIGHT_REACHED");
        }

        long correlationId =
                correlationGenerator.incrementAndGet();

        RequestContext context =
                new RequestContext(
                        correlationId,
                        sessionId,
                        clientMsgId,
                        requestXml);

        contexts.put(correlationId, context);

        return context;
    }

    public RequestContext get(long correlationId) {
        return contexts.get(correlationId);
    }

    public void remove(long correlationId) {
        contexts.remove(correlationId);
    }

    public int size() {
        return contexts.size();
    }

    public long getCurrentInflight() {
        return contexts.size();
    }

    public long getCorrelationCounter() {
        return correlationGenerator.get();
    }

    public void complete(long correlationId,
                         String responseXml) {

        RequestContext context =
                contexts.remove(correlationId);

        if (context != null) {

            context.getCompletionSink()
                    .tryEmitValue(responseXml);
        }
    }

    public void fail(long correlationId,
                     Throwable error) {

        RequestContext context =
                contexts.remove(correlationId);

        if (context != null) {

            context.getCompletionSink()
                    .tryEmitError(error);
        }
    }
}

