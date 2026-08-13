package com.rkp.gateway.session;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class SessionManager {

    private final ConcurrentHashMap<String, ClientSession> sessions =
            new ConcurrentHashMap<>();

    private final AtomicLong sessionCounter = new AtomicLong();

    public String nextSessionId() {
        return String.format("S%012d", sessionCounter.incrementAndGet());
    }

    public ClientSession create(String sessionId) {

        ClientSession session = new ClientSession(sessionId);

        sessions.put(sessionId, session);

        return session;
    }

    public ClientSession get(String sessionId) {
        return sessions.get(sessionId);
    }

    public void remove(String sessionId) {
        sessions.remove(sessionId);
    }

    public boolean exists(String sessionId) {
        return sessions.containsKey(sessionId);
    }

    public int size() {
        return sessions.size();
    }

    public long getSessionCounter() {
        return sessionCounter.get();
    }
}
