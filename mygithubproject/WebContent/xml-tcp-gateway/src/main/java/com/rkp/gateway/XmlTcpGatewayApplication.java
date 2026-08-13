package com.rkp.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.rkp.gateway.config.GatewayConfig;

@SpringBootApplication
@EnableConfigurationProperties(GatewayConfig.class)
public class XmlTcpGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(XmlTcpGatewayApplication.class, args);
	}

}
