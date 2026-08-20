package com.rkp.gateway.downstream;

import com.rkp.gateway.context.RequestContext;
import reactor.core.publisher.Mono;

public interface DownstreamClient {

    String systemName();

    Mono<DownstreamResult> call(RequestContext context);
}