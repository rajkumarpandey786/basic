package com.rkp.gateway.handler;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.stereotype.Component;

import com.rkp.gateway.context.ContextRegistry;
import com.rkp.gateway.context.RequestContext;
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

    private static final AttributeKey<String> SESSION_ID =
            AttributeKey.valueOf("SESSION_ID");

    private final XmlCodec codec;
    private final SessionManager sessionManager;
    private final MessageRouter router;
    private final ContextRegistry contextRegistry;
    private final TransactionOrchestrator transactionOrchestrator;

    public GatewayHandler(XmlCodec codec,
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

    public Mono<Void> handle(NettyInbound inbound,
                             NettyOutbound outbound) {

        AtomicReference<Channel> channelRef = new AtomicReference<>();

        inbound.withConnection(connection -> {

            Channel channel = connection.channel();
            channelRef.set(channel);

            String sessionId = channel.attr(SESSION_ID).get();

            if (sessionId == null) {

                sessionId = sessionManager.nextSessionId();

                channel.attr(SESSION_ID).set(sessionId);

                ClientSession session =
                        sessionManager.create(sessionId);

                session.setConnection(connection);

                System.out.println("SESSION CREATED : " + sessionId);
            }

            final String sid = sessionId;

            connection.onDispose(() -> {

                sessionManager.remove(sid);

                System.out.println("SESSION REMOVED : " + sid);
            });
        });

        return outbound.send(

                inbound.receive()
                        .retain()

                        .flatMap(byteBuf -> {

                            try {

                                Channel channel = channelRef.get();

                                String sessionId =
                                        channel.attr(SESSION_ID).get();

                                String xml =
                                        byteBuf.toString(
                                                StandardCharsets.UTF_8);

                                return process(sessionId, xml)

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

    private Mono<String> process(String sessionId,
                                 String xml) {

        ClientSession session =
                sessionManager.get(sessionId);

        if (session == null) {

            session = sessionManager.create(sessionId);
        }

        session.touch();

        Map<String, String> request =
                codec.parse(xml);

        String type = request.get("rec");

        if ("TXN".equals(type)) {

            if (!session.isReady(
                    router.getConfig().getProtocol().isRequireSignon(),
                    router.getConfig().getProtocol().isRequireKeyExchange())) {

                return Mono.just(codec.build(
                        XmlMessages.errorResponse(
                                request.get("msgId"),
                                "SESSION_NOT_READY")));
            }

            RequestContext context;

            try {

                context = contextRegistry.create(
                        sessionId,
                        request.get("msgId"),
                        xml);

            } catch (IllegalStateException ex) {

                return Mono.just(codec.build(
                        XmlMessages.errorResponse(
                                request.get("msgId"),
                                "SYSTEM_BUSY")));
            }

            transactionOrchestrator.process(context).subscribe();

            return context.getCompletionSink().asMono();
        }

        Map<String, String> response =
                router.route(session, request);

        return Mono.just(codec.build(response));
    }
}

