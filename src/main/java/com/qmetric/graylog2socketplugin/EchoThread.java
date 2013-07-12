package com.qmetric.graylog2socketplugin;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EchoThread extends Thread {

    protected Socket socket;

    protected volatile boolean isRunning = true;

    private Queue<String> messages = new ConcurrentLinkedQueue<String>();

    public EchoThread(Socket clientSocket) {
        this.socket = clientSocket;
    }

    public void run() {
        DataOutputStream out;
        try {
            out = new DataOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        String line;
        while (isRunning) {
            try {
                while (!messages.isEmpty()) {
                    line = messages.poll();
                    if (line != null) {
                        out.writeBytes(line+ "\n");
                        out.flush();
                    }
                }
            } catch (IOException e) {
                isRunning = false;
                return;
            }

            try
            {
                sleep(1000);
            }
            catch (InterruptedException e)
            {
                e.printStackTrace();
            }
        }
    }

    public void publish(final String message) {
        messages.offer(message);
    }

    public boolean isRunning() {
        return this.isRunning;
    }
}
