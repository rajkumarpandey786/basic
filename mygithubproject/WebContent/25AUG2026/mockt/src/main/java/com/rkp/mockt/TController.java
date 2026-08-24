package com.rkp.mockt;

import java.time.Duration;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

@RestController
public class TController {

    @PostMapping(
            value = "/api/process",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<String> process(
            @RequestBody String request) {

        return Mono.delay(
                Duration.ofMillis(500))

                .map(i ->
                        "{\"responseCode\":\"00\"," +
                        "\"responseMessage\":\"APPROVED\"}");
    }
}