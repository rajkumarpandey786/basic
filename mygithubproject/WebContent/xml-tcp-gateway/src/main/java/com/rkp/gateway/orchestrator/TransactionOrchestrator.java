package com.rkp.gateway.orchestrator;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.rkp.gateway.config.GatewayConfig;
import com.rkp.gateway.context.ContextRegistry;
import com.rkp.gateway.context.RequestContext;
import com.rkp.gateway.downstream.DownstreamManager;
import com.rkp.gateway.rules.ExecutionRuleEngine;
import com.rkp.gateway.xml.XmlCodec;

import reactor.core.publisher.Mono;

@Component
public class TransactionOrchestrator {

	private final ContextRegistry registry;
	private final XmlCodec codec;
	private final GatewayConfig config;
	private final ExecutionRuleEngine ruleEngine;
	private final DownstreamManager downstreamManager;

	public TransactionOrchestrator(DownstreamManager downstreamManager,
			ContextRegistry registry,
			XmlCodec codec,
			GatewayConfig config,
			ExecutionRuleEngine ruleEngine) {

		this.downstreamManager = downstreamManager;
		this.registry = registry;
		this.codec = codec;
		this.config = config;
		this.ruleEngine = ruleEngine;
	}

	public Mono<String> process(RequestContext context) {

		return downstreamManager.execute(context)
		        .timeout(Duration.ofMillis(
		                config.getDownstream().getTransactionTimeoutMs()))

		        .map(results -> {

		            Map<String, String> responseCodes =
		                    new LinkedHashMap<>();

		            for (Map.Entry<String, Map<String, String>> e :
		                    results.entrySet()) {

		                responseCodes.put(
		                        e.getKey(),
		                        e.getValue().getOrDefault(
		                                "responseCode",
		                                "96"));
		            }

		            AggregatedResult result =
		                    ruleEngine.evaluate(responseCodes);

		            Map<String, String> response =
		                    new LinkedHashMap<>();

		            response.put("rec", "TXN_RESP");
		            response.put("msgId", context.getClientMsgId());
		            response.put("correlationId",
		                    String.valueOf(context.getCorrelationId()));
		            response.put("respCode", result.responseCode());
		            response.put("respMsg", result.message());

		            return codec.build(response);
		        })

		        .onErrorResume(ex -> {

		            Map<String, String> response =
		                    new LinkedHashMap<>();

		            response.put("rec", "TXN_RESP");
		            response.put("msgId", context.getClientMsgId());
		            response.put("correlationId",
		                    String.valueOf(context.getCorrelationId()));
		            response.put("respCode", "91");
		            response.put("respMsg", "TIMEOUT");

		            return Mono.just(codec.build(response));
		        })

		        .doOnSuccess(xml ->
		                registry.complete(
		                        context.getCorrelationId(),
		                        xml))

		        .doOnError(ex ->
		                registry.fail(
		                        context.getCorrelationId(),
		                        ex));
	}
}

