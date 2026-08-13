package com.rkp.load;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class TerminalClient {

    private final String host;
    private final int port;
    private final String terminalId;
    private final int tps;
    private final MetricsCollector metrics;

    private final Map<String, Long> inflight =
            new ConcurrentHashMap<>();

    private Socket socket;
    private InputStream in;
    private OutputStream out;

    private long counter;

    public TerminalClient(String host,
                          int port,
                          String terminalId,
                          int tps,
                          MetricsCollector metrics) {

        this.host = host;
        this.port = port;
        this.terminalId = terminalId;
        this.tps = tps;
        this.metrics = metrics;
    }

    public void start() {

        try {

            socket = new Socket(host, port);

            socket.setKeepAlive(true);

            in = socket.getInputStream();

            out = socket.getOutputStream();

            signon();

            keyExchange();

            startReceiver();

            startSender();

        } catch (Exception e) {

            throw new RuntimeException(e);
        }
    }

    private void signon() throws Exception {

        sendSync(
                "<root>" +
                "<rec>SIGNON</rec>" +
                "<msgId>S-" + terminalId + "</msgId>" +
                "<terminalId>" + terminalId + "</terminalId>" +
                "</root>");
    }

    private void keyExchange() throws Exception {

        sendSync(
                "<root>" +
                "<rec>KEY_EXCHANGE</rec>" +
                "<msgId>K-" + terminalId + "</msgId>" +
                "<terminalId>" + terminalId + "</terminalId>" +
                "</root>");
    }

    private void startSender() {

        ScheduledExecutorService scheduler =
                Executors.newSingleThreadScheduledExecutor();

        long interval = 1000L / tps;

        scheduler.scheduleAtFixedRate(() -> {

            try {

                String msgId =
                        terminalId + "-" +
                        String.format("%06d", ++counter);

                String xml =
                        "<root>" +
                        "<rec>TXN</rec>" +
                        "<msgId>" + msgId + "</msgId>" +
                        "<terminalId>" + terminalId + "</terminalId>" +
                        "<amount>100</amount>" +
                        "</root>";

                inflight.put(
                        msgId,
                        System.currentTimeMillis());

                send(xml);

                metrics.sent();

            } catch (Exception e) {

                metrics.error();
            }

        }, 0, interval, TimeUnit.MILLISECONDS);
    }

    private void startReceiver() {

        Thread receiver = new Thread(() -> {

            try {

                while (true) {

                    int b1 = in.read();

                    int b2 = in.read();

                    if (b1 < 0 || b2 < 0) {
                        break;
                    }

                    int length =
                            ((b1 & 0xFF) << 8) | (b2 & 0xFF);

                    byte[] data = in.readNBytes(length);

                    String xml =
                            new String(
                                    data,
                                    StandardCharsets.UTF_8);

                    String msgId = extract(xml);

                    Long start =
                            inflight.remove(msgId);

                    if (start == null) {

                        System.err.println(
                                terminalId +
                                " MISMATCH: " +
                                msgId);

                        metrics.error();

                    } else {

                        metrics.received(
                                System.currentTimeMillis() - start);
                    }
                }

            } catch (Exception e) {

                metrics.error();
            }

        });

        receiver.setDaemon(true);

        receiver.start();
    }

    private String extract(String xml) {

        int s = xml.indexOf("<msgId>");

        int e = xml.indexOf("</msgId>");

        if (s < 0 || e < 0) {
            return "";
        }

        return xml.substring(s + 7, e);
    }

    private void sendSync(String xml) throws Exception {

        send(xml);

        int b1 = in.read();

        int b2 = in.read();

        int len = ((b1 & 0xFF) << 8) | (b2 & 0xFF);

        in.readNBytes(len);
    }

    private synchronized void send(String xml) throws Exception {

        byte[] bytes =
                xml.getBytes(StandardCharsets.UTF_8);

        out.write((bytes.length >> 8) & 0xFF);

        out.write(bytes.length & 0xFF);

        out.write(bytes);

        out.flush();
    }
}