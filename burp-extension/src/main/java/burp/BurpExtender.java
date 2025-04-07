package burp;

import java.io.PrintWriter;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.JOptionPane;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Component;
import java.util.Map;

/**
 * Burp Suite扩展主类
 */
public class BurpExtender implements IBurpExtender, IHttpListener, ITab {

    // Burp回调
    public static IBurpExtenderCallbacks callbacks;
    
    // 辅助对象
    public static IExtensionHelpers helpers;
    
    // 标准输出和错误输出
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    
    // 线程池
    private ExecutorService threadPool;
    
    // 请求计数器
    private static final AtomicInteger requestCounter = new AtomicInteger(0);
    
    // GUI界面
    private GUI gui;

    /**
     * 扩展注册方法
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 初始化回调
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // 设置扩展名称
        callbacks.setExtensionName("Guts - Web漏洞扫描工具");

        // 输出启动信息
        stdout.println("Guts 扩展已加载");
        stdout.println("作者: moonshot");
        stdout.println("版本: 1.0.0");
        
        // 创建线程池
        threadPool = Executors.newFixedThreadPool(10);

        // 创建UI界面
        SwingUtilities.invokeLater(() -> {
            // 创建GUI实例
            gui = new GUI(callbacks);
            
            // 设置自定义UI组件
            callbacks.customizeUiComponent(gui);
            
            // 将主面板添加到Burp的UI
            callbacks.addSuiteTab(BurpExtender.this);
            
            // 注册HTTP监听器
            callbacks.registerHttpListener(BurpExtender.this);
        });
    }
    
    /**
     * 实现ITab接口的getTabCaption方法
     */
    @Override
    public String getTabCaption() {
        return "Guts";
    }
    
    /**
     * 实现ITab接口的getUiComponent方法
     */
    @Override
    public Component getUiComponent() {
        return gui;
    }

    /**
     * 处理HTTP请求
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 如果插件未启动或者不是响应消息，直接返回
        if (!gui.isRunning() || messageIsRequest) {
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
            stdout.println("URL被过滤: " + url);
            return;
        }
        
        // 增加请求计数
        int count = requestCounter.incrementAndGet();
        Config.REQUEST_COUNT = count;
        
        // 生成请求ID
        final String requestId = String.valueOf(count);
        
        // 异步处理请求
        threadPool.submit(() -> {
            try {
                stdout.println("[" + requestId + "] 处理HTTP消息: " + url);
                
                // 保存请求和响应到临时文件，确保持久性
                IHttpRequestResponsePersisted persistedRequest = callbacks.saveBuffersToTempFiles(messageInfo);
                
                // 转发请求到 Guts 服务器
                stdout.println("[" + requestId + "] 转发请求到Guts服务器: " + url);
                Map<String, String> result = gui.getClient().forwardRequest(persistedRequest);
                
                // 创建日志条目
                LogEntry logEntry = new LogEntry(
                    requestId,
                    persistedRequest,
                    requestInfo.getUrl(),
                    requestInfo.getMethod(),
                    result
                );
                
                // 添加到日志表格
                gui.addLogEntry(logEntry);
                
                // 日志调试信息
                if ("200".equals(result.get("status"))) {
                    stdout.println("[" + requestId + "] 请求已成功转发: " + url);
                    Config.SUCCESS_COUNT++;
                } else {
                    stderr.println("[" + requestId + "] 请求转发失败: " + url + " (" + result.get("status") + ")");
                    Config.FAIL_COUNT++;
                }
            } catch (Exception e) {
                stderr.println("[" + requestId + "] 处理HTTP消息异常: " + e.getMessage());
                Config.FAIL_COUNT++;
            }
        });
    }
} 