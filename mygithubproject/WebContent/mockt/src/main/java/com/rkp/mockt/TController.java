package com.rkp.mockt;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.Duration;

@RestController
public class TController {

    @PostMapping(
            value = "/api/process",
            consumes = MediaType.APPLICATION_XML_VALUE,
            produces = MediaType.APPLICATION_XML_VALUE)
    public Mono<String> process(String request) {

        return Mono.delay(Duration.ofMillis(1500))

                .map(i ->
                        "<root>" +
                        "<respCode>00</respCode>" +
                        "<respMsg>T_APPROVED</respMsg>" +
                        "</root>");
    }
}