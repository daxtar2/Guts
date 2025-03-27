package burp;

import java.net.URL;
import java.util.Map;

/**
 * 日志条目类，用于记录请求响应
 */
public class LogEntry {
    private final String id;
    private final IHttpRequestResponse requestResponse;
    private final URL url;
    private final String method;
    private final Map<String, String> result;

    public LogEntry(String id, IHttpRequestResponse requestResponse, URL url, String method, Map<String, String> result) {
        this.id = id;
        this.requestResponse = requestResponse;
        this.url = url;
        this.method = method;
        this.result = result;
    }

    public String getId() {
        return id;
    }

    public IHttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public URL getUrl() {
        return url;
    }

    public String getMethod() {
        return method;
    }

    public Map<String, String> getResult() {
        return result;
    }
} 