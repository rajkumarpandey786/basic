~~~~~~~~~~~~~~ For Gateway ~~~~~~~~~~~~~
export GATEWAY_UPSTREAM_KEYSTORE_PATH=/Users/pandey/Development/product/topcore/xml-tcp-gateway/certs/gateway/gateway-server.p12

export GATEWAY_UPSTREAM_KEYSTORE_PASSWORD='your-secret'

export GATEWAY_UPSTREAM_TRUSTSTORE_PATH=/Users/pandey/Development/product/topcore/xml-tcp-gateway/certs/gateway/gateway-server-truststore.p12

export GATEWAY_UPSTREAM_TRUSTSTORE_PASSWORD='your-secret'

GATEWAY_T_KEYSTORE_PATH = /Users/pandey/Development/product/topcore/xml-tcp-gateway/certs/gateway/gatewayjks/gateway-t-client.jks
GATEWAY_T_KEYSTORE_PASSWORD = 
GATEWAY_T_TRUSTSTORE_PATH = /Users/pandey/Development/product/topcore/xml-tcp-gateway/certs/gateway/gateway-downstream-truststore.jks
GATEWAY_T_TRUSTSTORE_PASSWORD =

GATEWAY_P_KEYSTORE_PATH = /Users/pandey/Development/product/topcore/xml-tcp-gateway/certs/gateway/gatewayjks/gateway-p-client.jks
GATEWAY_P_KEYSTORE_PASSWORD = 
GATEWAY_P_TRUSTSTORE_PATH = /Users/pandey/Development/product/topcore/xml-tcp-gateway/certs/gateway/gateway-downstream-truststore.jks
GATEWAY_P_TRUSTSTORE_PASSWORD

*********** Check *************
ls -l "$GATEWAY_UPSTREAM_KEYSTORE_PATH"
ls -l "$GATEWAY_UPSTREAM_TRUSTSTORE_PATH"
----
keytool -list \
  -storetype PKCS12 \
  -keystore "$GATEWAY_UPSTREAM_KEYSTORE_PATH"
keytool -list \
  -storetype PKCS12 \
  -keystore "$GATEWAY_UPSTREAM_TRUSTSTORE_PATH"
*********** Check *************

~~~~~~~~~~~~~~ For T ~~~~~~~~~~~~~

export GATEWAY_T_KEYSTORE_PATH=/Users/pandey/Development/product/topcore/xml-tcp-gateway/certs/gateway/gateway-t-client.p12

export GATEWAY_T_KEYSTORE_PASSWORD='your-secret'

export GATEWAY_T_TRUSTSTORE_PATH=/Users/pandey/Development/product/topcore/xml-tcp-gateway/certs/gateway/gateway-downstream-truststore.p12

export GATEWAY_T_TRUSTSTORE_PASSWORD='your-secret'

~~~~~~~~~~~~~~ For P ~~~~~~~~~~~~~

export GATEWAY_P_KEYSTORE_PATH=/Users/pandey/Development/product/topcore/xml-tcp-gateway/certs/gateway/gateway-p-client.p12

export GATEWAY_P_KEYSTORE_PASSWORD='your-secret'

export GATEWAY_P_TRUSTSTORE_PATH=/Users/pandey/Development/product/topcore/xml-tcp-gateway/certs/gateway/gateway-downstream-truststore.p12

export GATEWAY_P_TRUSTSTORE_PASSWORD='your-secret'


# TLS / mTLS secrets
certs/**/*.key
certs/**/*.p12
certs/**/*.jks

# Local security configuration
.env
.env.*

----- upstream Flow

TerminalClient
     |
     | create SSLSocket
     |
     | TLS ClientHello
     v
Gateway
     |
     | ServerHello
     | Gateway certificate
     v
Terminal validates gateway certificate
     |
     | Terminal certificate
     v
Gateway validates terminal certificate
     |
     | TLS 1.3 handshake complete
     |
     v
SIGNON
     |
     v
KEY_EXCHANGE
     |
     v
TXN

-----Better Flow----

Terminal                                      Gateway
   |                                             |
   |------------- ClientHello ----------------->|
   |                                             |
   |<------------ ServerHello ------------------|
   |                                             |
   |<------- Gateway Certificate ---------------|
   |                                             |
   | Validate using                             |
   | terminal-client-truststore.p12             |
   |                                             |
   |                                             |
   |<------- CertificateRequest -----------------|
   |                                             |
   |------- Terminal Certificate -------------->|
   |                                             |
   |                                             | Validate using
   |                                             | gateway-server-
   |                                             | truststore.p12
   |                                             |
   |------- CertificateVerify ----------------->|
   |                                             |
   |<------ CertificateVerify ------------------|
   |                                             |
   |                                             |
   |========== TLS 1.3 established =============|
   |                                             |
   |------------- SIGNON ----------------------->|
   |<------------ SIGNON_RESP -------------------|
   |                                             |
   |---------- KEY_EXCHANGE -------------------->|
   |<--------- KEY_EXCHANGE_RESP ---------------|
   |                                             |
   |---------------- TXN ---------------------->|
   |<--------------- TXN_RESP ------------------|
   
   
   | Configuration | KeyStore | TrustStore |
| ------------- | -------- | ---------- |
| `NONE`        | ❌        | ❌          |
| `TLS`         | ✅        | ❌          |
| `MTLS`        | ✅        | ✅          |
   
   
   PKCS12 to JKS converting commnad sample:
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   keytool -importkeystore \
  -srckeystore terminal-client.p12 \
  -srcstoretype PKCS12 \
  -destkeystore terminal-client.jks \
  -deststoretype JKS
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~