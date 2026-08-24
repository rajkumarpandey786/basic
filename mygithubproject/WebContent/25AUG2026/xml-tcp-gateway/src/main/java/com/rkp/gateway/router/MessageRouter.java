package com.rkp.gateway.router;

import java.util.Map;

import org.springframework.stereotype.Component;

import com.rkp.gateway.config.GatewayConfig;
import com.rkp.gateway.session.ClientSession;
import com.rkp.gateway.xml.XmlMessages;

@Component
public class MessageRouter {

    private final GatewayConfig config;

    public MessageRouter(GatewayConfig config) {
        this.config = config;
    }

    public Map<String, String> route(ClientSession session,
                                     Map<String, String> request) {

        String type = request.get("rec");
        String msgId = request.get("msgId");

        switch (type) {

            case "ECHO":
                return XmlMessages.echoResponse(msgId);

            case "SIGNON":

                session.setSignedOn(true);

                String terminalId = request.get("terminalId");

                if (terminalId != null && !terminalId.isBlank()) {
                    session.setTerminalId(terminalId);
                }

                return XmlMessages.signonResponse(msgId);

            case "KEY_EXCHANGE":

                session.setKeyExchanged(true);

                return XmlMessages.keyExchangeResponse(
                        msgId,
                        "ABCDEF1234567890");

            case "SIGNOFF":

                if (!config.getProtocol().isEnableSignoff()) {

                    return XmlMessages.errorResponse(
                            msgId,
                            "SIGNOFF_DISABLED");
                }

                session.setSignedOn(false);
                session.setKeyExchanged(false);

                return XmlMessages.signoffResponse(msgId);

            case "TXN":

                if (!session.isReady(
                        config.getProtocol().isRequireSignon(),
                        config.getProtocol().isRequireKeyExchange())) {

                    return XmlMessages.errorResponse(
                            msgId,
                            "SESSION_NOT_READY");
                }

                return XmlMessages.txnAccepted(msgId);

            default:

                return XmlMessages.errorResponse(
                        msgId,
                        "UNKNOWN_MESSAGE");
        }
    }

    public GatewayConfig getConfig() {
        return config;
    }
}