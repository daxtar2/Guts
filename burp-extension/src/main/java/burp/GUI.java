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
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;
import java.io.File;

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
    
    // 配置文件管理器
    private final ConfigFileManager configFileManager;
    
    // 结果刷新定时器
    private Timer resultRefreshTimer;
    
    // 扫描结果缓存
    private List<Map<String, Object>> scanResultsCache = new ArrayList<>();
    
    /**
     * 构造函数
     */
    public GUI(IBurpExtenderCallbacks callbacks) {
        this.client = new GutsClient(Config.TARGET_HOST, Config.TARGET_PORT);
        
        // 配置文件路径 - 优先使用自定义路径（用户可以在扩展设置中配置），如果没有则使用默认路径
        String configPath = System.getProperty("guts.config.path");
        if (configPath == null || configPath.isEmpty()) {
            // 尝试从Burp的扩展设置中获取
            configPath = callbacks.loadExtensionSetting("guts.config.path");
        }
        
        // 如果仍然没有配置，使用默认路径
        if (configPath == null || configPath.isEmpty()) {
            configPath = "../config/config.yaml";
            // 提示用户可以配置路径
            BurpExtender.stdout.println("未配置配置文件路径，使用默认路径: " + configPath);
            BurpExtender.stdout.println("您可以通过在Burp启动时添加JVM参数 -Dguts.config.path=您的路径 来自定义配置文件路径");
            BurpExtender.stdout.println("或者在扩展设置中设置 guts.config.path");
        }
        
        this.configFileManager = new ConfigFileManager(configPath);
        
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
                logTable.getHttpLogTableModel().clearLog();
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
        formPanel.setLayout(new GridLayout(8, 2, 5, 10));  // 增加一行用于配置文件路径
        
        // 配置文件路径
        formPanel.add(new JLabel("配置文件路径:"));
        JPanel pathPanel = new JPanel(new BorderLayout());
        JTextField configPathField = new JTextField(configFileManager.getConfigFilePath());
        configPathField.setPreferredSize(new Dimension(150, configPathField.getPreferredSize().height));
        JButton browseButton = new JButton("浏览...");
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            fileChooser.setDialogTitle("选择配置文件");
            int result = fileChooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                configPathField.setText(selectedFile.getAbsolutePath());
            }
        });
        pathPanel.add(configPathField, BorderLayout.CENTER);
        pathPanel.add(browseButton, BorderLayout.EAST);
        formPanel.add(pathPanel);
        
        // 服务器配置
        formPanel.add(new JLabel("服务器地址:"));
        hostField = new JTextField(Config.TARGET_HOST);
        formPanel.add(hostField);
        
        formPanel.add(new JLabel("服务器端口:"));
        portField = new JTextField(String.valueOf(Config.TARGET_PORT));
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
        saveButton.addActionListener(e -> {
            // 保存配置文件路径
            String newConfigPath = configPathField.getText().trim();
            if (!newConfigPath.equals(configFileManager.getConfigFilePath())) {
                // 更新配置文件路径设置
                BurpExtender.callbacks.saveExtensionSetting("guts.config.path", newConfigPath);
                
                // 提示用户需要重新加载扩展以应用新路径
                JOptionPane.showMessageDialog(this, 
                    "配置文件路径已更改，需要重新加载扩展才能生效。",
                    "需要重新加载", JOptionPane.INFORMATION_MESSAGE);
            }
            
            // 继续保存其他配置
            saveConfigFromUI();
        });
        
        // 重置按钮
        JButton resetButton = new JButton("重置配置");
        resetButton.addActionListener(e -> {
            configPathField.setText(configFileManager.getConfigFilePath());
            loadConfigToUI();
        });
        
        // 创建使用API配置按钮
        JButton useApiConfigButton = new JButton("使用API配置");
        useApiConfigButton.addActionListener(e -> {
            // 切换到API配置模式
            switchToApiConfig();
        });
        
        // 创建使用文件配置按钮
        JButton useFileConfigButton = new JButton("使用文件配置");
        useFileConfigButton.addActionListener(e -> {
            // 切换到文件配置模式
            switchToFileConfig();
        });
        
        // 添加按钮到按钮面板
        buttonPanel.add(saveButton);
        buttonPanel.add(resetButton);
        buttonPanel.add(useApiConfigButton);
        buttonPanel.add(useFileConfigButton);
        
        // 创建包含所有配置面板的标签页
        JTabbedPane configTabs = new JTabbedPane();
        
        // 基本配置面板
        JPanel basicPanel = new JPanel(new BorderLayout());
        basicPanel.add(formPanel, BorderLayout.NORTH);
        basicPanel.add(buttonPanel, BorderLayout.SOUTH);
        configTabs.addTab("基本配置", basicPanel);
        
        // 创建配置面板，默认使用ConfigFileManager
        createFilterAndTemplateConfigTabs(configTabs, true);
        
        // 添加配置标签页到配置面板
        configPanel.add(configTabs, BorderLayout.CENTER);
    }
    
    /**
     * 创建过滤和模板配置标签页
     */
    private void createFilterAndTemplateConfigTabs(JTabbedPane configTabs, boolean useFileConfig) {
        // 移除已有的标签页（如果有）
        while (configTabs.getTabCount() > 1) {
            configTabs.remove(1);
        }
        
        if (useFileConfig) {
            // 使用配置文件方式
            FilterConfigPanel filterPanel = new FilterConfigPanel(configFileManager);
            TemplateConfigPanel templatePanel = new TemplateConfigPanel(configFileManager);
            
            configTabs.addTab("流量过滤", filterPanel);
            configTabs.addTab("模板过滤", templatePanel);
        } else {
            // 使用API方式
            FilterConfigPanel filterPanel = new FilterConfigPanel(client);
            TemplateConfigPanel templatePanel = new TemplateConfigPanel(client);
            
            configTabs.addTab("流量过滤", filterPanel);
            configTabs.addTab("模板过滤", templatePanel);
        }
    }
    
    /**
     * 切换到API配置模式
     */
    private void switchToApiConfig() {
        JTabbedPane configTabs = (JTabbedPane) configPanel.getComponent(0);
        createFilterAndTemplateConfigTabs(configTabs, false);
        JOptionPane.showMessageDialog(this, "已切换到API配置模式", "配置模式", JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * 切换到文件配置模式
     */
    private void switchToFileConfig() {
        JTabbedPane configTabs = (JTabbedPane) configPanel.getComponent(0);
        createFilterAndTemplateConfigTabs(configTabs, true);
        JOptionPane.showMessageDialog(this, "已切换到文件配置模式", "配置模式", JOptionPane.INFORMATION_MESSAGE);
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
        portField.setText(String.valueOf(Config.TARGET_PORT));
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
        Config.TARGET_PORT = Integer.parseInt(portField.getText().trim());
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
        if (isRunning.get()) {
            return;
        }
        
        // 保存配置
        saveConfigFromUI();
        
        // 设置按钮状态
        toggleButton.setText("停止服务");
        isRunning.set(true);
        
        // 创建线程池
        executor = Executors.newFixedThreadPool(10);
        
        // 初始化计数器
        Config.REQUEST_COUNT = 0;
        Config.SUCCESS_COUNT = 0;
        Config.FAIL_COUNT = 0;
        
        // 更新状态
        updateStats();
        
        // 开始定时刷新
        startResultRefresh();
        
        BurpExtender.stdout.println("Guts 被动扫描服务已启动");
    }
    
    /**
     * 停止服务
     */
    private void stopService() {
        if (!isRunning.get()) {
            return;
        }
        
        // 设置按钮状态
        toggleButton.setText("启动服务");
        isRunning.set(false);
        
        // 关闭线程池
        if (executor != null) {
            executor.shutdown();
            try {
                executor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                BurpExtender.stderr.println("关闭线程池时发生错误: " + e.getMessage());
            }
        }
        
        // 停止定时刷新
        stopResultRefresh();
        
        BurpExtender.stdout.println("Guts 被动扫描服务已停止");
    }
    
    /**
     * 刷新统计信息
     */
    private void refreshStats() {
        try {
            Map<String, Object> stats = client.getScanStats();
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
     * 开始定时刷新结果
     */
    private void startResultRefresh() {
        if (resultRefreshTimer != null) {
            resultRefreshTimer.stop();
        }
        
        // 创建定时器，每10秒刷新一次
        resultRefreshTimer = new Timer(10000, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                refreshResults();
                updateStats();
            }
        });
        
        resultRefreshTimer.start();
        BurpExtender.stdout.println("结果刷新定时器已启动");
    }
    
    /**
     * 停止定时刷新结果
     */
    private void stopResultRefresh() {
        if (resultRefreshTimer != null) {
            resultRefreshTimer.stop();
            resultRefreshTimer = null;
            BurpExtender.stdout.println("结果刷新定时器已停止");
        }
    }
    
    /**
     * 刷新扫描结果
     */
    private void refreshResults() {
        if (!isRunning.get()) {
            return;
        }
        
        try {
            // 获取最新的扫描结果
            List<Map<String, Object>> latestResults = client.getScanResults(1, 100);
            
            // 如果没有新结果，直接返回
            if (latestResults.isEmpty()) {
                return;
            }
            
            // 更新表格数据
            HttpLogTableModel model = logTable.getHttpLogTableModel();
            List<LogEntry> entries = model.getAllLogEntries();
            
            // 遍历最新结果
            for (Map<String, Object> result : latestResults) {
                // 检查结果是否已存在
                boolean found = false;
                String resultUrl = (String) result.get("target");
                
                if (resultUrl == null) {
                    continue;
                }
                
                // 遍历日志条目，查找匹配的URL
                for (int i = 0; i < entries.size(); i++) {
                    LogEntry entry = entries.get(i);
                    if (resultUrl.equals(entry.getUrl().toString())) {
                        // 更新已有条目
                        Map<String, String> updatedResult = new HashMap<>();
                        updatedResult.put("status", "200");
                        updatedResult.put("scanStatus", "success");
                        updatedResult.put("severity", (String) result.get("severity"));
                        updatedResult.put("vulnName", (String) result.get("name"));
                        
                        model.updateLogEntry(i, updatedResult);
                        found = true;
                        break;
                    }
                }
                
                // 如果结果不存在，记录日志
                if (!found) {
                    BurpExtender.stdout.println("发现新的扫描结果，但没有匹配的请求日志: " + resultUrl);
                }
            }
            
            // 更新缓存
            scanResultsCache = latestResults;
            
        } catch (Exception e) {
            BurpExtender.stderr.println("刷新扫描结果时发生错误: " + e.getMessage());
        }
    }
    
    /**
     * 更新统计数据
     */
    private void updateStats() {
        if (!isRunning.get()) {
            return;
        }
        
        try {
            // 获取扫描统计数据
            Map<String, Object> stats = client.getScanStats();
            
            // 更新请求计数
            int requestCount = Config.REQUEST_COUNT;
            lbRequestCount.setText(String.valueOf(requestCount));
            
            // 更新成功计数
            int totalVulns = 0;
            if (stats.containsKey("total")) {
                totalVulns = ((Number) stats.get("total")).intValue();
            }
            Config.SUCCESS_COUNT = totalVulns;
            lbSuccesCount.setText(String.valueOf(totalVulns));
            
            // 更新失败计数
            lbFailCount.setText(String.valueOf(Config.FAIL_COUNT));
            
            // 更新统计面板上的详细数据
            JPanel statsDetailPanel = (JPanel) statsPanel.getComponent(1);
            statsDetailPanel.removeAll();
            
            // 显示严重程度统计
            statsDetailPanel.setLayout(new GridLayout(5, 2, 5, 10));
            
            statsDetailPanel.add(new JLabel("总漏洞数:"));
            statsDetailPanel.add(new JLabel(String.valueOf(totalVulns)));
            
            // 按严重程度显示
            String[] severities = {"critical", "high", "medium", "low", "info"};
            for (String severity : severities) {
                int count = 0;
                if (stats.containsKey("severity_" + severity)) {
                    count = ((Number) stats.get("severity_" + severity)).intValue();
                }
                
                JLabel severityLabel = new JLabel(severity.substring(0, 1).toUpperCase() + severity.substring(1) + ":");
                JLabel countLabel = new JLabel(String.valueOf(count));
                
                // 根据严重程度设置颜色
                if ("critical".equals(severity)) {
                    severityLabel.setForeground(Color.RED);
                    countLabel.setForeground(Color.RED);
                } else if ("high".equals(severity)) {
                    severityLabel.setForeground(new Color(255, 69, 0));
                    countLabel.setForeground(new Color(255, 69, 0));
                } else if ("medium".equals(severity)) {
                    severityLabel.setForeground(Color.ORANGE);
                    countLabel.setForeground(Color.ORANGE);
                }
                
                statsDetailPanel.add(severityLabel);
                statsDetailPanel.add(countLabel);
            }
            
            statsDetailPanel.revalidate();
            statsDetailPanel.repaint();
            
        } catch (Exception e) {
            BurpExtender.stderr.println("更新统计数据时发生错误: " + e.getMessage());
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
    
    /**
     * 获取配置文件管理器
     */
    public ConfigFileManager getConfigFileManager() {
        return configFileManager;
    }
} 