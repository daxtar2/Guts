package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 插件主界面
 */
public class GUI extends JPanel {
    
    // UI组件
    private JTabbedPane tabbedPane;
    private JPanel mainPanel;
    private JPanel configPanel;
    private JPanel logPanel;
    private JPanel statsPanel;
    
    // 控制按钮
    private JToggleButton toggleButton;
    private JButton clearButton;
    private JButton refreshConfigButton;
    
    // 配置组件
    private JTextField hostField;
    private JTextField portField;
    private JTextField timeoutField;
    private JTextField intervalField;
    private JCheckBox forwardAllCheckBox;
    private JCheckBox autoStartCheckBox;
    private JCheckBox sslInsecureCheckBox;
    
    // 日志表格
    private HttpLogTable logTable;
    
    // HTTP消息查看器
    public static IMessageEditor requestViewer;
    public static IMessageEditor responseViewer;
    public static IMessageEditor proxyRspViewer;
    
    // 统计标签
    public static JLabel lbRequestCount;
    public static JLabel lbSuccesCount;
    public static JLabel lbFailCount;
    
    // 线程控制
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private ExecutorService executor;
    
    // 客户端
    private final GutsClient client;
    
    /**
     * 构造函数
     */
    public GUI(IBurpExtenderCallbacks callbacks) {
        this.client = new GutsClient();
        
        // 主面板设置
        setLayout(new BorderLayout());
        
        // 创建标签页面板
        tabbedPane = new JTabbedPane();
        createMainPanel();
        createConfigPanel();
        createLogPanel(callbacks);
        createStatsPanel();
        
        // 添加标签页
        tabbedPane.addTab("主要控制", mainPanel);
        tabbedPane.addTab("高级配置", configPanel);
        tabbedPane.addTab("请求日志", logPanel);
        tabbedPane.addTab("统计信息", statsPanel);
        
        // 添加标签页面板到主面板
        add(tabbedPane, BorderLayout.CENTER);
        
        // 加载初始配置
        loadConfigToUI();
        
        // 如果设置了自动启动，则启动服务
        if (Config.AUTO_START) {
            startService();
        }
    }
    
    /**
     * 创建主控制面板
     */
    private void createMainPanel() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());
        
        // 创建控制面板
        JPanel controlPanel = new JPanel();
        controlPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        controlPanel.setLayout(new GridLayout(3, 1, 5, 10));
        
        // 创建开关按钮
        toggleButton = new JToggleButton("启动服务");
        toggleButton.setFont(new Font("Dialog", Font.BOLD, 14));
        toggleButton.addActionListener(e -> {
            if (toggleButton.isSelected()) {
                startService();
            } else {
                stopService();
            }
        });
        
        // 创建清除按钮
        clearButton = new JButton("清除日志");
        clearButton.setFont(new Font("Dialog", Font.PLAIN, 13));
        clearButton.addActionListener(e -> {
            if (logTable != null) {
                logTable.getHttpLogTableModel().clearLogs();
            }
        });
        
        // 创建刷新配置按钮
        refreshConfigButton = new JButton("刷新远程配置");
        refreshConfigButton.setFont(new Font("Dialog", Font.PLAIN, 13));
        refreshConfigButton.addActionListener(e -> {
            Config.loadRemoteConfig(client);
            loadConfigToUI();
            JOptionPane.showMessageDialog(this, "远程配置已刷新", "配置更新", JOptionPane.INFORMATION_MESSAGE);
        });
        
        // 添加按钮到控制面板
        controlPanel.add(toggleButton);
        controlPanel.add(clearButton);
        controlPanel.add(refreshConfigButton);
        
        // 创建描述面板
        JPanel descPanel = new JPanel();
        descPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        descPanel.setLayout(new BorderLayout());
        
        // 添加描述文本
        JTextArea descText = new JTextArea();
        descText.setEditable(false);
        descText.setLineWrap(true);
        descText.setWrapStyleWord(true);
        descText.setText("Guts被动漏洞扫描插件\n\n" +
                "该插件将Burp Suite捕获的HTTP流量转发到Guts被动扫描引擎，实现自动化安全漏洞检测。\n\n" +
                "使用方法：\n" +
                "1. 配置Guts服务器地址和端口\n" +
                "2. 点击'启动服务'按钮开始捕获和转发流量\n" +
                "3. 在请求日志标签页查看已转发的请求\n" +
                "4. 在统计信息标签页查看检测结果统计\n\n" +
                "高级配置选项允许您自定义过滤规则和转发行为。");
        
        descPanel.add(new JScrollPane(descText), BorderLayout.CENTER);
        
        // 添加控制面板和描述面板到主面板
        mainPanel.add(controlPanel, BorderLayout.NORTH);
        mainPanel.add(descPanel, BorderLayout.CENTER);
    }
    
    /**
     * 创建配置面板
     */
    private void createConfigPanel() {
        configPanel = new JPanel();
        configPanel.setLayout(new BorderLayout());
        
        // 创建表单面板
        JPanel formPanel = new JPanel();
        formPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        formPanel.setLayout(new GridLayout(7, 2, 5, 10));
        
        // 服务器配置
        formPanel.add(new JLabel("服务器地址:"));
        hostField = new JTextField(Config.TARGET_HOST);
        formPanel.add(hostField);
        
        formPanel.add(new JLabel("服务器端口:"));
        portField = new JTextField(Config.TARGET_PORT);
        formPanel.add(portField);
        
        // 连接配置
        formPanel.add(new JLabel("连接超时(毫秒):"));
        timeoutField = new JTextField(String.valueOf(Config.TIMEOUT));
        formPanel.add(timeoutField);
        
        formPanel.add(new JLabel("请求间隔(毫秒):"));
        intervalField = new JTextField(String.valueOf(Config.INTERVAL_TIME));
        formPanel.add(intervalField);
        
        // 过滤配置
        formPanel.add(new JLabel("转发所有请求:"));
        forwardAllCheckBox = new JCheckBox("", Config.FORWARD_ALL);
        formPanel.add(forwardAllCheckBox);
        
        // 自动启动配置
        formPanel.add(new JLabel("自动启动服务:"));
        autoStartCheckBox = new JCheckBox("", Config.AUTO_START);
        formPanel.add(autoStartCheckBox);
        
        // SSL配置
        formPanel.add(new JLabel("不验证SSL证书:"));
        sslInsecureCheckBox = new JCheckBox("", Config.SSL_INSECURE);
        formPanel.add(sslInsecureCheckBox);
        
        // 创建按钮面板
        JPanel buttonPanel = new JPanel();
        buttonPanel.setBorder(new EmptyBorder(0, 10, 10, 10));
        buttonPanel.setLayout(new FlowLayout(FlowLayout.RIGHT));
        
        // 保存按钮
        JButton saveButton = new JButton("保存配置");
        saveButton.addActionListener(e -> saveConfigFromUI());
        
        // 重置按钮
        JButton resetButton = new JButton("重置配置");
        resetButton.addActionListener(e -> loadConfigToUI());
        
        // 添加按钮到按钮面板
        buttonPanel.add(saveButton);
        buttonPanel.add(resetButton);
        
        // 添加表单面板和按钮面板到配置面板
        configPanel.add(formPanel, BorderLayout.NORTH);
        configPanel.add(buttonPanel, BorderLayout.SOUTH);
    }
    
    /**
     * 创建日志面板
     */
    private void createLogPanel(IBurpExtenderCallbacks callbacks) {
        logPanel = new JPanel();
        logPanel.setLayout(new BorderLayout());
        
        // 创建日志表格
        logTable = new HttpLogTable(new HttpLogTableModel());
        
        // 创建请求/响应查看器
        JPanel viewersPanel = new JPanel();
        viewersPanel.setLayout(new GridLayout(3, 1));
        
        // 创建Burp消息编辑器
        IExtensionHelpers helpers = callbacks.getHelpers();
        requestViewer = callbacks.createMessageEditor(null, false);
        responseViewer = callbacks.createMessageEditor(null, false);
        proxyRspViewer = callbacks.createMessageEditor(null, false);
        
        // 创建查看器面板
        JSplitPane reqRespSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        reqRespSplitPane.setResizeWeight(0.5);
        
        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.add(new JLabel("原始请求"), BorderLayout.NORTH);
        reqPanel.add(requestViewer.getComponent(), BorderLayout.CENTER);
        
        JPanel respPanel = new JPanel(new BorderLayout());
        respPanel.add(new JLabel("原始响应"), BorderLayout.NORTH);
        respPanel.add(responseViewer.getComponent(), BorderLayout.CENTER);
        
        reqRespSplitPane.setLeftComponent(reqPanel);
        reqRespSplitPane.setRightComponent(respPanel);
        
        JPanel proxyRespPanel = new JPanel(new BorderLayout());
        proxyRespPanel.add(new JLabel("Guts响应"), BorderLayout.NORTH);
        proxyRespPanel.add(proxyRspViewer.getComponent(), BorderLayout.CENTER);
        
        // 分割日志表格和查看器
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.3);
        splitPane.setTopComponent(new JScrollPane(logTable));
        
        JSplitPane bottomSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        bottomSplitPane.setResizeWeight(0.6);
        bottomSplitPane.setTopComponent(reqRespSplitPane);
        bottomSplitPane.setBottomComponent(proxyRespPanel);
        
        splitPane.setBottomComponent(bottomSplitPane);
        
        // 添加分割面板到日志面板
        logPanel.add(splitPane, BorderLayout.CENTER);
    }
    
    /**
     * 创建统计面板
     */
    private void createStatsPanel() {
        statsPanel = new JPanel();
        statsPanel.setLayout(new BorderLayout());
        
        JPanel statsContentPanel = new JPanel();
        statsContentPanel.setLayout(new BoxLayout(statsContentPanel, BoxLayout.Y_AXIS));
        statsContentPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // 添加统计信息
        JPanel basicStatsPanel = new JPanel(new GridLayout(3, 2, 10, 5));
        basicStatsPanel.setBorder(BorderFactory.createTitledBorder("基本统计"));
        
        basicStatsPanel.add(new JLabel("总请求数:"));
        lbRequestCount = new JLabel("0");
        basicStatsPanel.add(lbRequestCount);
        
        basicStatsPanel.add(new JLabel("成功请求数:"));
        lbSuccesCount = new JLabel("0");
        basicStatsPanel.add(lbSuccesCount);
        
        basicStatsPanel.add(new JLabel("失败请求数:"));
        lbFailCount = new JLabel("0");
        basicStatsPanel.add(lbFailCount);
        
        statsContentPanel.add(basicStatsPanel);
        
        // 添加刷新按钮
        JButton refreshStatsButton = new JButton("刷新统计数据");
        refreshStatsButton.addActionListener(e -> refreshStats());
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(refreshStatsButton);
        
        // 添加面板到统计面板
        statsPanel.add(statsContentPanel, BorderLayout.NORTH);
        statsPanel.add(buttonPanel, BorderLayout.SOUTH);
    }
    
    /**
     * 从UI加载配置
     */
    private void loadConfigToUI() {
        hostField.setText(Config.TARGET_HOST);
        portField.setText(Config.TARGET_PORT);
        timeoutField.setText(String.valueOf(Config.TIMEOUT));
        intervalField.setText(String.valueOf(Config.INTERVAL_TIME));
        forwardAllCheckBox.setSelected(Config.FORWARD_ALL);
        autoStartCheckBox.setSelected(Config.AUTO_START);
        sslInsecureCheckBox.setSelected(Config.SSL_INSECURE);
    }
    
    /**
     * 保存UI配置到Config
     */
    private void saveConfigFromUI() {
        // 验证端口
        try {
            Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "端口必须是数字", "配置错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // 验证超时
        try {
            Integer.parseInt(timeoutField.getText().trim());
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "超时必须是数字", "配置错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // 验证间隔
        try {
            Integer.parseInt(intervalField.getText().trim());
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "间隔必须是数字", "配置错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // 保存配置
        Config.TARGET_HOST = hostField.getText().trim();
        Config.TARGET_PORT = portField.getText().trim();
        Config.TIMEOUT = Integer.parseInt(timeoutField.getText().trim());
        Config.INTERVAL_TIME = Integer.parseInt(intervalField.getText().trim());
        Config.FORWARD_ALL = forwardAllCheckBox.isSelected();
        Config.AUTO_START = autoStartCheckBox.isSelected();
        Config.SSL_INSECURE = sslInsecureCheckBox.isSelected();
        
        JOptionPane.showMessageDialog(this, "配置已保存", "配置更新", JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * 启动服务
     */
    private void startService() {
        if (!isRunning.get()) {
            isRunning.set(true);
            toggleButton.setText("停止服务");
            toggleButton.setSelected(true);
            
            // 创建线程池
            executor = Executors.newFixedThreadPool(2);
            
            // 启动统计刷新任务
            executor.submit(() -> {
                while (isRunning.get()) {
                    refreshStats();
                    try {
                        Thread.sleep(5000);  // 每5秒刷新一次
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            });
            
            BurpExtender.stdout.println("Guts被动扫描服务已启动");
        }
    }
    
    /**
     * 停止服务
     */
    private void stopService() {
        if (isRunning.get()) {
            isRunning.set(false);
            toggleButton.setText("启动服务");
            toggleButton.setSelected(false);
            
            // 关闭线程池
            if (executor != null) {
                executor.shutdownNow();
                executor = null;
            }
            
            BurpExtender.stdout.println("Guts被动扫描服务已停止");
        }
    }
    
    /**
     * 刷新统计信息
     */
    private void refreshStats() {
        try {
            var stats = client.getScanStats();
            if (!stats.isEmpty() && stats.containsKey("total")) {
                SwingUtilities.invokeLater(() -> {
                    lbRequestCount.setText(String.valueOf(Config.REQUEST_COUNT));
                    lbSuccesCount.setText(String.valueOf(Config.SUCCESS_COUNT));
                    lbFailCount.setText(String.valueOf(Config.FAIL_COUNT));
                });
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("刷新统计信息失败: " + e.getMessage());
        }
    }
    
    /**
     * 添加日志条目
     */
    public void addLogEntry(LogEntry logEntry) {
        if (logTable != null) {
            logTable.getHttpLogTableModel().addLogEntry(logEntry);
        }
    }
    
    /**
     * 检查服务是否正在运行
     */
    public boolean isRunning() {
        return isRunning.get();
    }
    
    /**
     * 获取客户端
     */
    public GutsClient getClient() {
        return client;
    }
} 