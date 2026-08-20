package com.rkp.gateway.session;

import reactor.netty.Connection;

public class ClientSession {

    private final String sessionId;

    private volatile String terminalId;

    private volatile boolean signedOn;

    private volatile boolean keyExchanged;

    private volatile long lastActivity;

    private volatile Connection connection;

    public ClientSession(String sessionId) {
        this.sessionId = sessionId;
        this.lastActivity = System.currentTimeMillis();
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getTerminalId() {
        return terminalId;
    }

    public void setTerminalId(String terminalId) {
        this.terminalId = terminalId;
    }

    public boolean isSignedOn() {
        return signedOn;
    }

    public void setSignedOn(boolean signedOn) {
        this.signedOn = signedOn;
    }

    public boolean isKeyExchanged() {
        return keyExchanged;
    }

    public void setKeyExchanged(boolean keyExchanged) {
        this.keyExchanged = keyExchanged;
    }

    public long getLastActivity() {
        return lastActivity;
    }

    public void touch() {
        this.lastActivity = System.currentTimeMillis();
    }

    public Connection getConnection() {
        return connection;
    }

    public void setConnection(Connection connection) {
        this.connection = connection;
    }

    public boolean isReady(boolean requireSignon,
                           boolean requireKeyExchange) {

        if (requireSignon && !signedOn) {
            return false;
        }

        if (requireKeyExchange && !keyExchanged) {
            return false;
        }

        return true;
    }
}
