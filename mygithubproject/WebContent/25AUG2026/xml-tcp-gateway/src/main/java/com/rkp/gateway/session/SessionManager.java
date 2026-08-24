package com.rkp.gateway.session;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.springframework.stereotype.Component;

import com.rkp.gateway.observability.GatewayLogger;

@Component
public class SessionManager {

    private static final Logger log =
            GatewayLogger.getLogger(SessionManager.class);

    private final ConcurrentHashMap<String, ClientSession> sessions =
            new ConcurrentHashMap<>();

    private final AtomicLong sessionCounter = new AtomicLong();

    public String nextSessionId() {

        String sessionId =
                String.format("S%012d",
                        sessionCounter.incrementAndGet());

        GatewayLogger.debug(log,
                "Generated session id {}",
                sessionId);

        return sessionId;
    }

    public ClientSession create(String sessionId) {

        ClientSession session = new ClientSession(sessionId);

        sessions.put(sessionId, session);

        GatewayLogger.info(log,
                "Session created {} activeSessions={}",
                sessionId,
                sessions.size());

        return session;
    }

    public ClientSession get(String sessionId) {

        ClientSession session = sessions.get(sessionId);

        if (session == null) {

            GatewayLogger.warn(log,
                    "Session lookup failed {}",
                    sessionId);
        }

        return session;
    }

    public void remove(String sessionId) {

        ClientSession removed = sessions.remove(sessionId);

        if (removed != null) {

            GatewayLogger.info(log,
                    "Session removed {} activeSessions={}",
                    sessionId,
                    sessions.size());

        } else {

            GatewayLogger.warn(log,
                    "Attempted to remove unknown session {}",
                    sessionId);
        }
    }

    public boolean exists(String sessionId) {

        boolean exists = sessions.containsKey(sessionId);

        if (!exists) {

            GatewayLogger.debug(log,
                    "Session does not exist {}",
                    sessionId);
        }

        return exists;
    }

    public int size() {
        return sessions.size();
    }

    public long getSessionCounter() {
        return sessionCounter.get();
    }
}