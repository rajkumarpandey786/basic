package com.rkp.gateway.orchestrator;


import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.rkp.gateway.context.ContextRegistry;
import com.rkp.gateway.context.RequestContext;
import com.rkp.gateway.xml.XmlCodec;

import reactor.core.publisher.Mono;

@Component
public class TransactionProcessor {

private final ContextRegistry registry;
private final XmlCodec codec;

public TransactionProcessor(ContextRegistry registry,
                            XmlCodec codec) {
    this.registry = registry;
    this.codec = codec;
}

public Mono<String> process(RequestContext context) {

    return Mono.delay(Duration.ofMillis(50))
            .map(ignore -> {

                Map<String, String> response = new LinkedHashMap<>();

                response.put("rec", "TXN_RESP");
                response.put("msgId", context.getClientMsgId());
                response.put("respCode", "00");
                response.put("respMsg", "APPROVED");

                return codec.build(response);
            })
            .doOnSuccess(xml -> registry.complete(
                    context.getCorrelationId(),
                    xml))
            .doOnError(ex -> registry.fail(
                    context.getCorrelationId(),
                    ex));
}

}

