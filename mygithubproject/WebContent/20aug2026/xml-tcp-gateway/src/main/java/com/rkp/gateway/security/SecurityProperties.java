package com.rkp.gateway.security;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "gateway.security")
public class SecurityProperties {

    private final Upstream upstream =
            new Upstream();

    private final Downstream downstream =
            new Downstream();

    public Upstream getUpstream() {
        return upstream;
    }

    public Downstream getDownstream() {
        return downstream;
    }

    public static class Upstream {

        private final MtlsProperties mtls =
                new MtlsProperties();

        public MtlsProperties getMtls() {
            return mtls;
        }
    }

    public static class Downstream {

        /*
         * Do NOT make this final because Spring Boot
         * may replace the map while binding YAML.
         */
        private Map<String, SystemSecurity> systems =
                new LinkedHashMap<>();

        public Map<String, SystemSecurity> getSystems() {
            return systems;
        }

        public void setSystems(
                Map<String, SystemSecurity> systems) {

            this.systems = systems;
        }
    }

    public static class SystemSecurity {

        private MtlsProperties mtls =
                new MtlsProperties();

        public MtlsProperties getMtls() {
            return mtls;
        }

        public void setMtls(
                MtlsProperties mtls) {

            this.mtls = mtls;
        }
    }
}