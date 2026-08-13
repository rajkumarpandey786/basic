package com.rkp.gateway.downstream;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.rkp.gateway.config.GatewayConfig;
import com.rkp.gateway.context.RequestContext;

import reactor.core.publisher.Mono;

@Component
public class DownstreamManager {

    private final GatewayConfig config;
    private final TClient tClient;
    private final PClient pClient;

    public DownstreamManager(GatewayConfig config,
                             TClient tClient,
                             PClient pClient) {

        this.config = config;
        this.tClient = tClient;
        this.pClient = pClient;
    }

    public Mono<Map<String, Map<String, String>>> execute(RequestContext context) {

        Map<String, Mono<Map<String, String>>> calls =
                new LinkedHashMap<>();

        List<String> active =
                config.getDownstream().getActive();

        if (active.contains("T")) {
            calls.put("T", tClient.call(context));
        }

        if (active.contains("P")) {
            calls.put("P", pClient.call(context));
        }

        if (calls.isEmpty()) {
            return Mono.just(new LinkedHashMap<>());
        }

        return Mono.zip(
                calls.values(),
                results -> {

                    Map<String, Map<String, String>> output =
                            new LinkedHashMap<>();

                    int index = 0;

                    for (String key : calls.keySet()) {
                        output.put(
                                key,
                                (Map<String, String>) results[index++]);
                    }

                    return output;
                });
    }
}
