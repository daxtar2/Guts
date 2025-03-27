package burp;

import java.io.PrintWriter;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Burp Suite 插件入口
 */
public class BurpExtender implements IBurpExtender, IHttpListener {

    // Burp 扩展回调
    public static IBurpExtenderCallbacks callbacks;
    
    // Burp 帮助工具
    public static IExtensionHelpers helpers;
    
    // 输出流
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    
    // GUI 实例
    private GUI gui;
    
    // 线程池
    private ExecutorService threadPool;
    
    /**
     * 插件注册方法
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 保存回调
        BurpExtender.callbacks = callbacks;
        
        // 设置插件名称
        callbacks.setExtensionName("Guts 被动漏洞扫描插件");
        
        // 获取帮助工具
        helpers = callbacks.getHelpers();
        
        // 创建输出流
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // 创建线程池
        threadPool = Executors.newFixedThreadPool(10);
        
        // 创建 GUI
        gui = new GUI(callbacks);
        
        // 注册 HTTP 监听器
        callbacks.registerHttpListener(this);
        
        // 添加标签页
        callbacks.addSuiteTab(new BurpSuiteTab("Guts 扫描器", gui));
        
        // 显示启动信息
        stdout.println("Guts 被动漏洞扫描插件 已加载");
        stdout.println("默认服务器地址: " + Config.TARGET_HOST + ":" + Config.TARGET_PORT);
    }
    
    /**
     * HTTP 请求响应处理
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 只处理响应消息
        if (messageIsRequest || !gui.isRunning()) {
            return;
        }
        
        // 只处理代理和重放器的消息
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY && toolFlag != IBurpExtenderCallbacks.TOOL_REPEATER) {
            return;
        }
        
        // 获取请求信息
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        String url = requestInfo.getUrl().toString();
        
        // 应用过滤规则
        if (Config.shouldFilter(url)) {
            return;
        }
        
        // 异步处理请求
        threadPool.submit(() -> {
            try {
                // 转发请求到 Guts 服务器
                Map<String, String> result = gui.getClient().forwardRequest(messageInfo);
                
                // 保存请求和响应到临时文件
                IHttpRequestResponsePersisted persistedRequest = callbacks.saveBuffersToTempFiles(messageInfo);
                
                // 创建日志条目
                LogEntry logEntry = new LogEntry(
                    String.valueOf(Config.REQUEST_COUNT),
                    persistedRequest,
                    requestInfo.getUrl(),
                    requestInfo.getMethod(),
                    result
                );
                gui.addLogEntry(logEntry);
                
                // 日志调试信息
                if ("200".equals(result.get("status"))) {
                    stdout.println("请求已成功转发: " + url);
                } else {
                    stderr.println("请求转发失败: " + url + " (" + result.get("status") + ")");
                }
            } catch (Exception e) {
                stderr.println("处理HTTP消息异常: " + e.getMessage());
            }
        });
    }
    
    /**
     * 日志 ID 生成器
     */
    private static class LogIDGenerator {
        private static int lastId = 0;
        
        public static synchronized int nextId() {
            return ++lastId;
        }
    }
}

/**
 * Burp Suite 标签页实现
 */
class BurpSuiteTab implements ITab {
    private final String tabName;
    private final GUI gui;
    
    public BurpSuiteTab(String tabName, GUI gui) {
        this.tabName = tabName;
        this.gui = gui;
    }
    
    @Override
    public String getTabCaption() {
        return tabName;
    }
    
    @Override
    public java.awt.Component getUiComponent() {
        return gui;
    }
} 