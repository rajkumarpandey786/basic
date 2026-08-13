package com.rkp.gateway.context;


import reactor.core.publisher.Sinks;

public class RequestContext {

private final long correlationId;
private final String sessionId;
private final String clientMsgId;
private final String requestXml;
private final long requestTime;

private volatile String downstreamRequest1;
private volatile String downstreamRequest2;

private volatile String response1;
private volatile String response2;

private final Sinks.One<String> completionSink = Sinks.one();

public RequestContext(long correlationId,
                      String sessionId,
                      String clientMsgId,
                      String requestXml) {

    this.correlationId = correlationId;
    this.sessionId = sessionId;
    this.clientMsgId = clientMsgId;
    this.requestXml = requestXml;
    this.requestTime = System.nanoTime();
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

public long getRequestTime() {
    return requestTime;
}

public String getDownstreamRequest1() {
    return downstreamRequest1;
}

public void setDownstreamRequest1(String downstreamRequest1) {
    this.downstreamRequest1 = downstreamRequest1;
}

public String getDownstreamRequest2() {
    return downstreamRequest2;
}

public void setDownstreamRequest2(String downstreamRequest2) {
    this.downstreamRequest2 = downstreamRequest2;
}

public String getResponse1() {
    return response1;
}

public void setResponse1(String response1) {
    this.response1 = response1;
}

public String getResponse2() {
    return response2;
}

public void setResponse2(String response2) {
    this.response2 = response2;
}

public Sinks.One<String> getCompletionSink() {
    return completionSink;
}

public long elapsedMicros() {
    return (System.nanoTime() - requestTime) / 1000;
}

}

