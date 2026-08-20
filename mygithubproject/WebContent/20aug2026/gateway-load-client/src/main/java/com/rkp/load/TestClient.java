package com.rkp.load;

import java.util.ArrayList;
import java.util.List;

public class TestClient {

    public static void main(String[] args) throws Exception {

        MetricsCollector metrics = new MetricsCollector();

        List<TerminalClient> clients = new ArrayList<>();


            String terminalId = String.format("TERM%03d", 1);

            TerminalClient client = new TerminalClient(
                    "localhost",
                    9000,
                    terminalId,
                    1,
                    metrics);

            clients.add(client);

        clients.forEach(TerminalClient::start);

        while (true) {

            Thread.sleep(1000);

            metrics.printAndReset();
            
        }
    }
}