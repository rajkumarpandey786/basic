package com.rkp.gateway.context;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import reactor.core.publisher.Sinks;

public class RequestContext {

    private final long correlationId;

    private final String sessionId;

    private final String clientMsgId;

    private final String requestXml;

    private final long gatewayStartNanos;

    private volatile long gatewayEndNanos;

    private volatile String terminalId;

    private Map<String, String> requestData =
            new HashMap<>();

    private final ConcurrentHashMap<String, DownstreamState>
            downstreamStates =
            new ConcurrentHashMap<>();

    private final Sinks.One<String> completionSink =
            Sinks.one();

    private final AtomicBoolean completed =
            new AtomicBoolean(false);

    public RequestContext(long correlationId,
                          String sessionId,
                          String clientMsgId,
                          String requestXml) {

        this.correlationId = correlationId;
        this.sessionId = sessionId;
        this.clientMsgId = clientMsgId;
        this.requestXml = requestXml;
        this.gatewayStartNanos = System.nanoTime();
    }

    public long getCorrelationId() {
        return correlationId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getClientMsgId() {
        return clientMsgId;
    }

    public String getRequestXml() {
        return requestXml;
    }

    public long getGatewayStartNanos() {
        return gatewayStartNanos;
    }

    public long getGatewayEndNanos() {
        return gatewayEndNanos;
    }

    public void markGatewayCompleted() {
        this.gatewayEndNanos = System.nanoTime();
        this.completed.set(true);
    }

    public boolean isCompleted() {
        return completed.get();
    }

    public long gatewayLatencyMicros() {

        long end = gatewayEndNanos == 0
                ? System.nanoTime()
                : gatewayEndNanos;

        return (end - gatewayStartNanos) / 1000;
    }

    public long gatewayLatencyMillis() {

        long end = gatewayEndNanos == 0
                ? System.nanoTime()
                : gatewayEndNanos;

        return (end - gatewayStartNanos) / 1_000_000;
    }

    public DownstreamState downstream(String systemName) {

        return downstreamStates.computeIfAbsent(
                systemName,
                key -> new DownstreamState());
    }

    public Map<String, DownstreamState> getDownstreamStates() {
        return downstreamStates;
    }

    public String getTerminalId() {
        return terminalId;
    }

    public void setTerminalId(String terminalId) {
        this.terminalId = terminalId;
    }

    public Map<String, String> getRequestData() {
        return requestData;
    }

    public void setRequestData(Map<String, String> requestData) {
        this.requestData = requestData;
    }

    public Sinks.One<String> getCompletionSink() {
        return completionSink;
    }

    public String summary() {

        StringBuilder sb = new StringBuilder();

        sb.append("corr=")
                .append(correlationId)
                .append(" session=")
                .append(sessionId)
                .append(" terminal=")
                .append(terminalId)
                .append(" msgId=")
                .append(clientMsgId)
                .append(" gatewayMs=")
                .append(gatewayLatencyMillis());

        downstreamStates.forEach((name, state) ->

                sb.append(" ")
                        .append(name)
                        .append("Ms=")
                        .append(state.latencyMillis()));

        return sb.toString();
    }
}