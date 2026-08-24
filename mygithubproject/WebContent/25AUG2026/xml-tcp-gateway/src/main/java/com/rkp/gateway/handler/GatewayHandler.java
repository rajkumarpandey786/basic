package com.rkp.gateway.handler;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.springframework.stereotype.Component;

import com.rkp.gateway.context.ContextRegistry;
import com.rkp.gateway.context.RequestContext;
import com.rkp.gateway.observability.GatewayLogger;
import com.rkp.gateway.observability.LogContext;
import com.rkp.gateway.observability.LogContextThreadLocalAccessor;
import com.rkp.gateway.orchestrator.TransactionOrchestrator;
import com.rkp.gateway.router.MessageRouter;
import com.rkp.gateway.session.ClientSession;
import com.rkp.gateway.session.SessionManager;
import com.rkp.gateway.xml.XmlCodec;
import com.rkp.gateway.xml.XmlMessages;

import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.util.AttributeKey;
import reactor.core.publisher.Mono;
import reactor.netty.NettyInbound;
import reactor.netty.NettyOutbound;

@Component
public class GatewayHandler {

    private static final Logger log =
            GatewayLogger.getLogger(GatewayHandler.class);

    private static final AttributeKey<String> SESSION_ID =
            AttributeKey.valueOf("SESSION_ID");

    private final XmlCodec codec;
    private final SessionManager sessionManager;
    private final MessageRouter router;
    private final ContextRegistry contextRegistry;
    private final TransactionOrchestrator transactionOrchestrator;

    public GatewayHandler(
            XmlCodec codec,
            SessionManager sessionManager,
            MessageRouter router,
            ContextRegistry contextRegistry,
            TransactionOrchestrator transactionOrchestrator) {

        this.codec = codec;
        this.sessionManager = sessionManager;
        this.router = router;
        this.contextRegistry = contextRegistry;
        this.transactionOrchestrator = transactionOrchestrator;
    }

    public Mono<Void> handle(
            NettyInbound inbound,
            NettyOutbound outbound) {

        AtomicReference<Channel> channelRef =
                new AtomicReference<>();

        inbound.withConnection(connection -> {

            Channel channel = connection.channel();

            channelRef.set(channel);

            String sessionId =
                    channel.attr(SESSION_ID).get();

            if (sessionId == null) {

                sessionId =
                        sessionManager.nextSessionId();

                channel.attr(SESSION_ID)
                        .set(sessionId);

                ClientSession session =
                        sessionManager.create(sessionId);

                session.setConnection(connection);

                GatewayLogger.info(
                        log,
                        "TCP session created session={}",
                        sessionId);
            }

            final String sid = sessionId;

            connection.onDispose(() -> {

                sessionManager.remove(sid);

                GatewayLogger.info(
                        log,
                        "TCP session removed session={}",
                        sid);
            });
        });

        return outbound.send(

                inbound.receive()
                        .retain()

                        .flatMap(byteBuf -> {

                            try {

                                Channel channel =
                                        channelRef.get();

                                String sessionId =
                                        channel.attr(SESSION_ID)
                                                .get();

                                String xml =
                                        byteBuf.toString(
                                                StandardCharsets.UTF_8);

                                return process(
                                        sessionId,
                                        xml)

                                        .map(response ->
                                                Unpooled.copiedBuffer(
                                                        response,
                                                        StandardCharsets.UTF_8));

                            } finally {

                                byteBuf.release();
                            }
                        })

        ).then();
    }

    private Mono<String> process(
            String sessionId,
            String xml) {

        ClientSession currentSession =
                sessionManager.get(sessionId);

        if (currentSession == null) {

            currentSession =
                    sessionManager.create(sessionId);
        }

        currentSession.touch();

        final ClientSession session =
                currentSession;

        Map<String, String> request =
                codec.parse(xml);

        String type =
                request.get("rec");

        /*
         * =========================================================
         * TRANSACTION
         * =========================================================
         */

        if ("TXN".equals(type)) {

            if (!session.isReady(
                    router.getConfig()
                            .getProtocol()
                            .isRequireSignon(),

                    router.getConfig()
                            .getProtocol()
                            .isRequireKeyExchange())) {

                GatewayLogger.warn(
                        log,
                        "TXN rejected session not ready session={} msgId={}",
                        sessionId,
                        request.get("msgId"));

                return Mono.just(
                        codec.build(
                                XmlMessages.errorResponse(
                                        request.get("msgId"),
                                        "SESSION_NOT_READY")));
            }

            RequestContext context;

            try {

                context =
                        contextRegistry.create(
                                sessionId,
                                request.get("msgId"),
                                xml);

                context.setTerminalId(
                        request.getOrDefault(
                                "terminalId",
                                ""));

                context.setRequestData(request);

            } catch (IllegalStateException ex) {

                GatewayLogger.error(
                        log,
                        "Unable to create request context session={} msgId={}",
                        sessionId,
                        request.get("msgId"));

                return Mono.just(
                        codec.build(
                                XmlMessages.errorResponse(
                                        request.get("msgId"),
                                        "SYSTEM_BUSY")));
            }

            /*
             * One LogContext is created for the complete transaction.
             */
            LogContext logContext =
                    new LogContext(
                            String.valueOf(
                                    context.getCorrelationId()));

            logContext.setSessionId(
                    context.getSessionId());

            logContext.setTerminalId(
                    context.getTerminalId());

            logContext.setClientMsgId(
                    context.getClientMsgId());

            /*
             * IMPORTANT:
             *
             * The logging must happen INSIDE the reactive chain.
             *
             * Otherwise LogContextHolder will not yet contain
             * the Reactor propagated LogContext.
             */
            return Mono.defer(() -> {

                GatewayLogger.info(
                        log,
                        "RX TXN terminal={} msgId={} size={}B",
                        context.getTerminalId(),
                        context.getClientMsgId(),
                        xml.length());

                return transactionOrchestrator
                        .process(context);

            }).contextWrite(
                    reactorContext ->
                            reactorContext.put(
                                    LogContextThreadLocalAccessor.KEY,
                                    logContext));
        }

        /*
         * =========================================================
         * NON-TRANSACTION MESSAGE
         * =========================================================
         */

        /*
         * No RequestContext/correlation ID exists for messages
         * such as SIGNON and KEY_EXCHANGE.
         *
         * Therefore session ID is used as the identifier.
         */
        LogContext logContext =
                new LogContext(sessionId);

        logContext.setSessionId(sessionId);

        return Mono.defer(() -> {

            GatewayLogger.info(
                    log,
                    "RX {} session={}",
                    type,
                    sessionId);

            Map<String, String> response =
                    router.route(
                            session,
                            request);

            GatewayLogger.info(
                    log,
                    "TX {} completed session={}",
                    type,
                    sessionId);

            return Mono.just(
                    codec.build(response));

        }).contextWrite(
                reactorContext ->
                        reactorContext.put(
                                LogContextThreadLocalAccessor.KEY,
                                logContext));
    }
}