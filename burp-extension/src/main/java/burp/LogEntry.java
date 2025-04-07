package burp;

import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 日志条目
 */
public class LogEntry {
    private final String id;
    private final IHttpRequestResponsePersisted requestResponse;
    private final URL url;
    private final String method;
    private Map<String, String> result;
    private final String timestamp;
    
    /**
     * 构造函数
     */
    public LogEntry(String id, IHttpRequestResponsePersisted requestResponse, URL url, String method, Map<String, String> result) {
        this.id = id;
        this.requestResponse = requestResponse;
        this.url = url;
        this.method = method;
        this.result = result != null ? result : new HashMap<>();
        
        // 添加时间戳
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        this.timestamp = dateFormat.format(new Date());
    }
    
    /**
     * 获取ID
     */
    public String getId() {
        return id;
    }
    
    /**
     * 获取请求响应对象
     */
    public IHttpRequestResponsePersisted getRequestResponse() {
        return requestResponse;
    }
    
    /**
     * 获取URL
     */
    public URL getUrl() {
        return url;
    }
    
    /**
     * 获取HTTP方法
     */
    public String getMethod() {
        return method;
    }
    
    /**
     * 获取结果
     */
    public Map<String, String> getResult() {
        return result;
    }
    
    /**
     * 设置结果
     */
    public void setResult(Map<String, String> result) {
        this.result = result;
    }
    
    /**
     * 获取时间戳
     */
    public String getTimestamp() {
        return timestamp;
    }
    
    /**
     * 获取状态代码
     */
    public String getStatusCode() {
        return result.getOrDefault("status", "N/A");
    }
    
    /**
     * 获取扫描结果
     */
    public String getScanStatus() {
        return result.getOrDefault("scanStatus", "处理中");
    }
    
    /**
     * 获取严重程度
     */
    public String getSeverity() {
        return result.getOrDefault("severity", "-");
    }
} 