package io.github.tortaje.hvault.testsupport;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/** Captures JUL records of one logger for the duration of a test. */
public final class LogCapture implements AutoCloseable {
    private final Logger logger;
    private final Level previousLevel;
    private final List<LogRecord> records = Collections.synchronizedList(new ArrayList<>());
    private final Handler handler;

    private LogCapture(String loggerName) {
        this.logger = Logger.getLogger(loggerName);
        this.previousLevel = logger.getLevel();
        this.handler = new Handler() {
            @Override public void publish(LogRecord r) { records.add(r); }
            @Override public void flush() { }
            @Override public void close() { }
        };
        handler.setLevel(Level.ALL);
        logger.setLevel(Level.ALL);
        logger.addHandler(handler);
    }

    public static LogCapture on(String loggerName) {
        return new LogCapture(loggerName);
    }

    public List<LogRecord> records() {
        synchronized (records) {
            return new ArrayList<>(records);
        }
    }

    /** Formatted messages (parameters included) and thrown exception messages. */
    public String allText() {
        SimpleFormatter f = new SimpleFormatter();
        StringBuilder sb = new StringBuilder();
        for (LogRecord r : records()) {
            sb.append(f.formatMessage(r)).append('\n');
            for (Throwable t = r.getThrown(); t != null; t = t.getCause()) {
                sb.append(t.getMessage()).append('\n');
            }
        }
        return sb.toString();
    }

    @Override public void close() {
        logger.removeHandler(handler);
        logger.setLevel(previousLevel);
    }
}
