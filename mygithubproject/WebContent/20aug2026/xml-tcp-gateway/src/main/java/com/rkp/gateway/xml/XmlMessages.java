package com.rkp.gateway.xml;

import java.util.LinkedHashMap;
import java.util.Map;

public final class XmlMessages {

    private XmlMessages() {}

    public static Map<String, String> echoResponse(String msgId) {
        return response("ECHO_RESP", msgId, "00", "ECHO SUCCESS");
    }

    public static Map<String, String> signonResponse(String msgId) {
        return response("SIGNON_RESP", msgId, "00", "SIGNON SUCCESS");
    }

    public static Map<String, String> signoffResponse(String msgId) {
        return response("SIGNOFF_RESP", msgId, "00", "SIGNOFF SUCCESS");
    }

    public static Map<String, String> keyExchangeResponse(String msgId, String sessionKey) {
        Map<String, String> m = response(
                "KEY_EXCHANGE_RESP",
                msgId,
                "00",
                "KEY EXCHANGE SUCCESS");

        m.put("sessionKey", sessionKey);

        return m;
    }

    public static Map<String, String> txnAccepted(String msgId) {
        return response("TXN_RESP", msgId, "00", "TXN ACCEPTED");
    }

    public static Map<String, String> errorResponse(String msgId, String message) {
        return response("ERROR", msgId, "96", message);
    }

    private static Map<String, String> response(
            String rec,
            String msgId,
            String code,
            String msg) {

        Map<String, String> m = new LinkedHashMap<>();

        m.put("rec", rec);
        m.put("msgId", msgId);
        m.put("respCode", code);
        m.put("respMsg", msg);

        return m;
    }
}