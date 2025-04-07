package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * 流量过滤配置面板类
 */
public class FilterConfigPanel extends JPanel {
    
    private final GutsClient client;
    private final ConfigFileManager configFileManager;
    
    // 配置面板的组件
    private JPanel formPanel;
    private JCheckBox sslCheckbox;
    private JTextField includeDomainField;
    private JTextField excludeDomainField;
    private JTextField filterSuffixField;
    
    // 配置数据
    private Map<String, Object> configData = new HashMap<>();
    
    /**
     * 构造函数 - 使用API
     */
    public FilterConfigPanel(GutsClient client) {
        this.client = client;
        this.configFileManager = null;
        
        initUI();
    }
    
    /**
     * 构造函数 - 使用本地配置文件
     */
    public FilterConfigPanel(ConfigFileManager configFileManager) {
        this.client = null;
        this.configFileManager = configFileManager;
        
        initUI();
    }
    
    /**
     * 初始化UI
     */
    private void initUI() {
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // 创建表单面板
        createFormPanel();
        
        // 创建按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton saveButton = new JButton("保存配置");
        saveButton.addActionListener(e -> saveConfig());
        
        JButton refreshButton = new JButton("刷新配置");
        refreshButton.addActionListener(e -> refreshConfig());
        
        buttonPanel.add(refreshButton);
        buttonPanel.add(saveButton);
        
        // 添加到主面板
        add(new JScrollPane(formPanel), BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
        
        // 加载配置
        refreshConfig();
    }
    
    /**
     * 创建表单面板
     */
    private void createFormPanel() {
        formPanel = new JPanel(new GridBagLayout());
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // 标题
        JLabel titleLabel = new JLabel("流量过滤配置");
        titleLabel.setFont(new Font("Dialog", Font.BOLD, 14));
        gbc.gridwidth = 2;
        formPanel.add(titleLabel, gbc);
        
        gbc.gridwidth = 1;
        gbc.gridy++;
        
        // SSL
        formPanel.add(new JLabel("启用SSL:"), gbc);
        sslCheckbox = new JCheckBox();
        gbc.gridx = 1;
        formPanel.add(sslCheckbox, gbc);
        
        // 包含域名
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("包含域名 (逗号分隔):"), gbc);
        includeDomainField = new JTextField(20);
        gbc.gridx = 1;
        formPanel.add(includeDomainField, gbc);
        
        // 排除域名
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("排除域名 (逗号分隔):"), gbc);
        excludeDomainField = new JTextField(20);
        gbc.gridx = 1;
        formPanel.add(excludeDomainField, gbc);
        
        // 过滤后缀
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("过滤后缀 (逗号分隔):"), gbc);
        filterSuffixField = new JTextField(20);
        gbc.gridx = 1;
        formPanel.add(filterSuffixField, gbc);
        
        // 提示信息
        gbc.gridx = 0;
        gbc.gridy++;
        gbc.gridwidth = 2;
        JTextArea infoArea = new JTextArea(
            "说明:\n" +
            "1. 包含域名: 只处理这些域名的请求 (为空则处理所有)\n" +
            "2. 排除域名: 不处理这些域名的请求\n" +
            "3. 过滤后缀: 不处理包含这些后缀的URL (如 .css, .js)\n" +
            "4. 启用SSL: 是否处理HTTPS请求"
        );
        infoArea.setEditable(false);
        infoArea.setBackground(new Color(240, 240, 240));
        infoArea.setBorder(BorderFactory.createEtchedBorder());
        gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(infoArea, gbc);
    }
    
    /**
     * 刷新配置
     */
    private void refreshConfig() {
        try {
            if (configFileManager != null) {
                // 从配置文件读取
                configData = configFileManager.getFilterConfig();
            } else if (client != null) {
                // 从API读取
                configData = client.getFilterConfig();
            }
            
            updateFormValues();
        } catch (Exception e) {
            BurpExtender.stderr.println("刷新流量过滤配置失败: " + e.getMessage());
            JOptionPane.showMessageDialog(this, "刷新流量过滤配置失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * 更新表单值
     */
    private void updateFormValues() {
        // 将配置数据应用到表单中
        boolean ssl = getBooleanValue(configData, "SSL");
        sslCheckbox.setSelected(ssl);
        
        List<String> includeDomains = getListValue(configData, "IncludeDomains");
        includeDomainField.setText(String.join(",", includeDomains));
        
        List<String> excludeDomains = getListValue(configData, "ExcludeDomains");
        excludeDomainField.setText(String.join(",", excludeDomains));
        
        List<String> filterSuffixes = getListValue(configData, "FilterSuffix");
        filterSuffixField.setText(String.join(",", filterSuffixes));
    }
    
    /**
     * 保存配置
     */
    private void saveConfig() {
        try {
            // 获取表单值
            Map<String, Object> newConfig = new HashMap<>();
            
            newConfig.put("SSL", sslCheckbox.isSelected());
            
            // 将逗号分隔的字符串转换为列表
            newConfig.put("IncludeDomains", splitToList(includeDomainField.getText()));
            newConfig.put("ExcludeDomains", splitToList(excludeDomainField.getText()));
            newConfig.put("FilterSuffix", splitToList(filterSuffixField.getText()));
            
            boolean success = false;
            
            if (configFileManager != null) {
                // 保存到配置文件
                success = configFileManager.updateFilterConfig(newConfig);
            } else if (client != null) {
                // 保存到API
                success = client.updateFilterConfig(newConfig);
            }
            
            if (success) {
                JOptionPane.showMessageDialog(this, "流量过滤配置保存成功!", "成功", JOptionPane.INFORMATION_MESSAGE);
                refreshConfig();
            } else {
                JOptionPane.showMessageDialog(this, "流量过滤配置保存失败!", "错误", JOptionPane.ERROR_MESSAGE);
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("保存流量过滤配置失败: " + e.getMessage());
            JOptionPane.showMessageDialog(this, "保存流量过滤配置失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * 获取配置中的布尔值
     */
    private boolean getBooleanValue(Map<String, Object> config, String key) {
        if (config.containsKey(key)) {
            Object value = config.get(key);
            if (value instanceof Boolean) {
                return (Boolean) value;
            }
        }
        return false;
    }
    
    /**
     * 获取配置中的列表值
     */
    @SuppressWarnings("unchecked")
    private List<String> getListValue(Map<String, Object> config, String key) {
        if (config.containsKey(key)) {
            Object value = config.get(key);
            if (value instanceof List) {
                return (List<String>) value;
            }
        }
        return new ArrayList<>();
    }
    
    /**
     * 将逗号分隔的字符串转换为列表
     */
    private List<String> splitToList(String text) {
        List<String> list = new ArrayList<>();
        if (text != null && !text.isEmpty()) {
            String[] items = text.split(",");
            for (String item : items) {
                String trimmed = item.trim();
                if (!trimmed.isEmpty()) {
                    list.add(trimmed);
                }
            }
        }
        return list;
    }
} 