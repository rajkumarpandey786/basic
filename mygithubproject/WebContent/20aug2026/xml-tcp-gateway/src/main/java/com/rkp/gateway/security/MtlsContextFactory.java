package com.rkp.gateway.security;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.springframework.stereotype.Component;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;

@Component
public class MtlsContextFactory {

    /**
     * Creates a Netty client SSL context for downstream mTLS.
     *
     * This factory is currently not wired into WebClientFactory.
     * That will be done in the next step.
     */
    public SslContext create(
            MtlsProperties properties) {

        if (properties == null) {
            throw new IllegalArgumentException(
                    "mTLS properties must not be null");
        }

        /*
         * mTLS is disabled.
         *
         * The caller can continue using normal HTTP.
         */
        if (!properties.isEnabled()) {
            return null;
        }

        try {

            KeyStoreProperties keyStoreProperties =
                    properties.getKeyStore();

            KeyStoreProperties trustStoreProperties =
                    properties.getTrustStore();

            /*
             * -----------------------------------------------------
             * LOAD CLIENT KEYSTORE
             * -----------------------------------------------------
             *
             * Contains:
             *
             *   Gateway private key
             *   Gateway client certificate
             */
            KeyStore keyStore =
                    loadKeyStore(keyStoreProperties);

            /*
             * -----------------------------------------------------
             * CREATE KEY MANAGER
             * -----------------------------------------------------
             *
             * KeyManagerFactory extracts the private key
             * and certificate from the keystore.
             */
            KeyManagerFactory keyManagerFactory =
                    KeyManagerFactory.getInstance(
                            KeyManagerFactory
                                    .getDefaultAlgorithm());

            keyManagerFactory.init(
                    keyStore,
                    keyStoreProperties.getPassword()
                            .toCharArray());

            /*
             * -----------------------------------------------------
             * LOAD TRUSTSTORE
             * -----------------------------------------------------
             *
             * Contains the CA/server certificates that the
             * gateway trusts.
             */
            KeyStore trustStore =
                    loadKeyStore(trustStoreProperties);

            /*
             * -----------------------------------------------------
             * CREATE TRUST MANAGER
             * -----------------------------------------------------
             */
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(
                            TrustManagerFactory
                                    .getDefaultAlgorithm());

            trustManagerFactory.init(trustStore);

            /*
             * -----------------------------------------------------
             * CREATE NETTY SSL CONTEXT
             * -----------------------------------------------------
             */
            SslContextBuilder builder =
                    SslContextBuilder.forClient()

                            .keyManager(
                                    keyManagerFactory)

                            .trustManager(
                                    trustManagerFactory);

            /*
             * Configure TLS protocol.
             */
            if (properties.getProtocol() != null
                    && !properties.getProtocol().isBlank()) {

                builder.protocols(
                        properties.getProtocol());
            }

            return builder.build();

        } catch (Exception ex) {

            throw new IllegalStateException(
                    "Unable to create mTLS SSL context",
                    ex);
        }
    }

    /**
     * Loads a Java KeyStore / TrustStore from disk.
     */
    private KeyStore loadKeyStore(
            KeyStoreProperties properties)
            throws Exception {

        if (properties == null) {

            throw new IllegalArgumentException(
                    "Keystore configuration must not be null");
        }

        String type =
                properties.getType();

        if (type == null ||
                type.isBlank()) {

            type = KeyStore.getDefaultType();
        }

        String path =
                properties.getPath();

        if (path == null ||
                path.isBlank()) {

            throw new IllegalArgumentException(
                    "Keystore path is not configured");
        }

        String password =
                properties.getPassword();

        if (password == null) {

            password = "";
        }

        KeyStore keyStore =
                KeyStore.getInstance(type);

        try (InputStream input =
                     new FileInputStream(path)) {

            keyStore.load(
                    input,
                    password.toCharArray());
        }

        return keyStore;
    }
}