package com.rkp.gateway.config;


import org.springframework.stereotype.Component;

import com.rkp.gateway.handler.GatewayHandler;

import io.netty.channel.ChannelOption;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import io.netty.handler.codec.LengthFieldPrepender;
import jakarta.annotation.PostConstruct;
import reactor.netty.DisposableServer;
import reactor.netty.tcp.TcpServer;

@Component
public class TcpServerConfig {

    private final GatewayConfig config;
    private final GatewayHandler gatewayHandler;

    private DisposableServer server;

    public TcpServerConfig(GatewayConfig config,
                           GatewayHandler gatewayHandler) {
        this.config = config;
        this.gatewayHandler = gatewayHandler;
    }

    @PostConstruct
    public void start() {

        GatewayConfig.Tcp tcp = config.getTcp();

        this.server = TcpServer.create()
                .host(tcp.getHost())
                .port(tcp.getPort())

                .option(ChannelOption.SO_REUSEADDR, true)
                .childOption(ChannelOption.SO_KEEPALIVE, tcp.isKeepAlive())
                .childOption(ChannelOption.TCP_NODELAY, tcp.isTcpNoDelay())
                .childOption(ChannelOption.SO_RCVBUF, tcp.getReceiveBuffer())
                .childOption(ChannelOption.SO_SNDBUF, tcp.getSendBuffer())

                .doOnConnection(conn -> conn.addHandlerFirst(
                        new LengthFieldBasedFrameDecoder(
                                tcp.getMaxFrameLength(),
                                0,
                                2,
                                0,
                                2)))

                .doOnConnection(conn -> conn.addHandlerLast(
                        new LengthFieldPrepender(2)))

                .handle(gatewayHandler::handle)

                .bindNow();

        System.out.println(
                "TCP Gateway started on " +
                tcp.getHost() + ":" + tcp.getPort());
    }

    public DisposableServer getServer() {
        return server;
    }
}