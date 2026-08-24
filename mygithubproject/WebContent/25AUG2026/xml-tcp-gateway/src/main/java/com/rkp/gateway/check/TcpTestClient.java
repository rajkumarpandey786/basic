package com.rkp.gateway.check;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class TcpTestClient {

public static void main(String[] args) throws Exception {

    try (Socket socket = new Socket("localhost", 9000)) {

        socket.setKeepAlive(true);
        socket.setTcpNoDelay(true);

        DataInputStream input =
                new DataInputStream(socket.getInputStream());

        DataOutputStream output =
                new DataOutputStream(socket.getOutputStream());

        send(output, input,
                "<root><rec>ECHO</rec><msgId>1001</msgId></root>");

        send(output, input,
                "<root><rec>SIGNON</rec><msgId>2001</msgId></root>");

        send(output, input,
                "<root><rec>KEY_EXCHANGE</rec><msgId>3001</msgId></root>");

        send(output, input,
                "<root><rec>SIGNOFF</rec><msgId>4001</msgId></root>");
    }
}

private static void send(DataOutputStream output,
                         DataInputStream input,
                         String xml) throws Exception {

    byte[] payload = xml.getBytes(StandardCharsets.UTF_8);

    System.out.println("-------------------------------------");
    System.out.println("CLIENT SEND:");
    System.out.println(xml);

    output.writeShort(payload.length);
    output.write(payload);
    output.flush();

    int length = input.readUnsignedShort();

    byte[] responseBytes = input.readNBytes(length);

    String response = new String(responseBytes, StandardCharsets.UTF_8);

    System.out.println("CLIENT RECEIVE:");
    System.out.println(response);
}

}
