package com.rkp.load;

import java.util.ArrayList;
import java.util.List;

public class LoadTestClient {

    public static void main(String[] args) throws Exception {

        MetricsCollector metrics = new MetricsCollector();

        List<TerminalClient> clients = new ArrayList<>();
        TerminalSecurityConfig securityConfig = null;

        for (int i = 1; i <= 10; i++) {

            String terminalId = String.format("TERM%03d", i);

            TerminalClient client = new TerminalClient(
                    "localhost",
                    9000,
                    terminalId,
                    100,
                    metrics, securityConfig);

            clients.add(client);
        }

        clients.forEach(TerminalClient::start);

        while (true) {

            Thread.sleep(1000);

            metrics.printAndReset();
        }
    }
}