package com.rkp.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "gateway")
public class GatewayConfig {

    private final Tcp tcp = new Tcp();
    private final Protocol protocol = new Protocol();
    private final Downstream downstream = new Downstream();

    public Tcp getTcp() {
        return tcp;
    }

    public Protocol getProtocol() {
        return protocol;
    }

    public Downstream getDownstream() {
        return downstream;
    }

    public static class Tcp {

        private String host;
        private int port;
        private boolean keepAlive;
        private boolean tcpNoDelay;
        private int receiveBuffer;
        private int sendBuffer;
        private int maxFrameLength;

        public String getHost() {
            return host;
        }

        public void setHost(String host) {
            this.host = host;
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            this.port = port;
        }

        public boolean isKeepAlive() {
            return keepAlive;
        }

        public void setKeepAlive(boolean keepAlive) {
            this.keepAlive = keepAlive;
        }

        public boolean isTcpNoDelay() {
            return tcpNoDelay;
        }

        public void setTcpNoDelay(boolean tcpNoDelay) {
            this.tcpNoDelay = tcpNoDelay;
        }

        public int getReceiveBuffer() {
            return receiveBuffer;
        }

        public void setReceiveBuffer(int receiveBuffer) {
            this.receiveBuffer = receiveBuffer;
        }

        public int getSendBuffer() {
            return sendBuffer;
        }

        public void setSendBuffer(int sendBuffer) {
            this.sendBuffer = sendBuffer;
        }

        public int getMaxFrameLength() {
            return maxFrameLength;
        }

        public void setMaxFrameLength(int maxFrameLength) {
            this.maxFrameLength = maxFrameLength;
        }
    }

    public static class Protocol {

        private boolean requireSignon;
        private boolean requireKeyExchange;
        private boolean requireEcho;
        private boolean enableSignoff;
        private int echoIntervalSeconds;

        public boolean isRequireSignon() {
            return requireSignon;
        }

        public void setRequireSignon(boolean requireSignon) {
            this.requireSignon = requireSignon;
        }

        public boolean isRequireKeyExchange() {
            return requireKeyExchange;
        }

        public void setRequireKeyExchange(boolean requireKeyExchange) {
            this.requireKeyExchange = requireKeyExchange;
        }

        public boolean isRequireEcho() {
            return requireEcho;
        }

        public void setRequireEcho(boolean requireEcho) {
            this.requireEcho = requireEcho;
        }

        public boolean isEnableSignoff() {
            return enableSignoff;
        }

        public void setEnableSignoff(boolean enableSignoff) {
            this.enableSignoff = enableSignoff;
        }

        public int getEchoIntervalSeconds() {
            return echoIntervalSeconds;
        }

        public void setEchoIntervalSeconds(int echoIntervalSeconds) {
            this.echoIntervalSeconds = echoIntervalSeconds;
        }
    }

    public static class Downstream {

        private int transactionTimeoutMs;
        private int maxInflightTransactions;

        private List<String> active = new ArrayList<>();

        private Map<String, SystemConfig> systems =
                new LinkedHashMap<>();

        public int getTransactionTimeoutMs() {
            return transactionTimeoutMs;
        }

        public void setTransactionTimeoutMs(int transactionTimeoutMs) {
            this.transactionTimeoutMs = transactionTimeoutMs;
        }

        public int getMaxInflightTransactions() {
            return maxInflightTransactions;
        }

        public void setMaxInflightTransactions(int maxInflightTransactions) {
            this.maxInflightTransactions = maxInflightTransactions;
        }

        public List<String> getActive() {
            return active;
        }

        public void setActive(List<String> active) {
            this.active = active;
        }

        public Map<String, SystemConfig> getSystems() {
            return systems;
        }

        public void setSystems(Map<String, SystemConfig> systems) {
            this.systems = systems;
        }

        public static class SystemConfig {

            private String url;
            private int connectTimeoutMs;
            private int responseTimeoutMs;
            private int maxConnections;

            public String getUrl() {
                return url;
            }

            public void setUrl(String url) {
                this.url = url;
            }

            public int getConnectTimeoutMs() {
                return connectTimeoutMs;
            }

            public void setConnectTimeoutMs(int connectTimeoutMs) {
                this.connectTimeoutMs = connectTimeoutMs;
            }

            public int getResponseTimeoutMs() {
                return responseTimeoutMs;
            }

            public void setResponseTimeoutMs(int responseTimeoutMs) {
                this.responseTimeoutMs = responseTimeoutMs;
            }

            public int getMaxConnections() {
                return maxConnections;
            }

            public void setMaxConnections(int maxConnections) {
                this.maxConnections = maxConnections;
            }
        }
    }
}