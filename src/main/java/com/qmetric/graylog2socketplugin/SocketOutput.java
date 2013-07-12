package com.qmetric.graylog2socketplugin;

import java.util.Map;
import java.util.HashMap;
import java.util.List;

import org.graylog2.plugin.GraylogServer;
import org.graylog2.plugin.outputs.MessageOutputConfigurationException;
import org.graylog2.plugin.outputs.OutputStreamConfiguration;
import org.graylog2.plugin.logmessage.LogMessage;
import org.graylog2.plugin.outputs.MessageOutput;
import java.io.*;
import java.net.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SocketOutput implements MessageOutput {

    private static final String NAME = "Socket Output";
    private static final int PORT = 1978;
	private static final Logger LOG = LoggerFactory.getLogger(SocketOutput.class);
	private ConnectionManager connectionManager;
	
	@Override
    public void write(List<LogMessage> messages, OutputStreamConfiguration streamConfig, GraylogServer server) throws Exception {
		
		LOG.debug("SocketOutput Messages Size " + messages.size());
        for (LogMessage message : messages) {
			connectionManager.publish(buildTailMessage(message));
        }
    }

	@Override
    public String getName() {
        return NAME;
    }

    @Override
    public void initialize(Map<String, String> config) throws MessageOutputConfigurationException {
		connectionManager = new ConnectionManager(PORT);
        connectionManager.start();
    }

    @Override
    public Map<String, String> getRequestedConfiguration() {
        return new HashMap<String, String>();
    }
    
    @Override
    public Map<String, String> getRequestedStreamConfiguration() {
        return new HashMap<String, String>();
    }

	private String buildTailMessage(LogMessage msg) {
		StringBuilder sb = new StringBuilder();
		int c = (int)msg.getCreatedAt();
		sb.append("host:").append(msg.getHost());
		sb.append(",date:").append(c);
		sb.append(",facility:").append(msg.getFacility());
		sb.append(",level:").append(msg.getLevel());
		String fullMessage = msg.getFullMessage();
		if ((fullMessage == null) || (fullMessage.isEmpty())) {
			sb.append(",message:").append(msg.getShortMessage());
		} else {
			sb.append(",message:").append(msg.getFullMessage());
		}
		return sb.toString();
	}

}
