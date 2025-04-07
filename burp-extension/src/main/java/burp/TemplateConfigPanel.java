package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * 模板配置面板类
 */
public class TemplateConfigPanel extends JPanel {
    
    private final GutsClient client;
    private final ConfigFileManager configFileManager;
    
    // 配置面板的组件
    private JPanel formPanel;
    private JComboBox<String> severityCombo;
    private JComboBox<String> excludeSeveritiesCombo;
    private JComboBox<String> protocolTypesCombo;
    private JComboBox<String> excludeProtocolTypesCombo;
    private JTextField authorsField;
    private JTextField tagsField;
    private JTextField excludeTagsField;
    private JTextField includeTagsField;
    private JTextField idsField;
    private JTextField excludeIdsField;
    
    // 配置数据
    private Map<String, Object> configData = new HashMap<>();
    
    /**
     * 构造函数 - 使用API
     */
    public TemplateConfigPanel(GutsClient client) {
        this.client = client;
        this.configFileManager = null;
        
        initUI();
    }
    
    /**
     * 构造函数 - 使用本地配置文件
     */
    public TemplateConfigPanel(ConfigFileManager configFileManager) {
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
        JLabel titleLabel = new JLabel("模板过滤配置");
        titleLabel.setFont(new Font("Dialog", Font.BOLD, 14));
        gbc.gridwidth = 2;
        formPanel.add(titleLabel, gbc);
        
        gbc.gridwidth = 1;
        gbc.gridy++;
        
        // 严重程度
        formPanel.add(new JLabel("严重程度:"), gbc);
        String[] severityOptions = {"critical", "high", "medium", "low", "info"};
        severityCombo = new JComboBox<>(severityOptions);
        severityCombo.setEditable(true);
        severityCombo.setSelectedItem("");
        gbc.gridx = 1;
        formPanel.add(severityCombo, gbc);
        
        // 排除严重程度
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("排除严重程度:"), gbc);
        excludeSeveritiesCombo = new JComboBox<>(severityOptions);
        excludeSeveritiesCombo.setEditable(true);
        excludeSeveritiesCombo.setSelectedItem("");
        gbc.gridx = 1;
        formPanel.add(excludeSeveritiesCombo, gbc);
        
        // 协议类型
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("协议类型:"), gbc);
        String[] protocolOptions = {"http", "dns", "file", "tcp", "headless"};
        protocolTypesCombo = new JComboBox<>(protocolOptions);
        protocolTypesCombo.setEditable(true);
        protocolTypesCombo.setSelectedItem("");
        gbc.gridx = 1;
        formPanel.add(protocolTypesCombo, gbc);
        
        // 排除协议类型
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("排除协议类型:"), gbc);
        excludeProtocolTypesCombo = new JComboBox<>(protocolOptions);
        excludeProtocolTypesCombo.setEditable(true);
        excludeProtocolTypesCombo.setSelectedItem("");
        gbc.gridx = 1;
        formPanel.add(excludeProtocolTypesCombo, gbc);
        
        // 作者
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("作者 (逗号分隔):"), gbc);
        authorsField = new JTextField(20);
        gbc.gridx = 1;
        formPanel.add(authorsField, gbc);
        
        // 标签
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("标签 (逗号分隔):"), gbc);
        tagsField = new JTextField(20);
        gbc.gridx = 1;
        formPanel.add(tagsField, gbc);
        
        // 排除标签
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("排除标签 (逗号分隔):"), gbc);
        excludeTagsField = new JTextField(20);
        gbc.gridx = 1;
        formPanel.add(excludeTagsField, gbc);
        
        // 包含标签
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("包含标签 (逗号分隔):"), gbc);
        includeTagsField = new JTextField(20);
        gbc.gridx = 1;
        formPanel.add(includeTagsField, gbc);
        
        // ID列表
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("ID列表 (逗号分隔):"), gbc);
        idsField = new JTextField(20);
        gbc.gridx = 1;
        formPanel.add(idsField, gbc);
        
        // 排除ID列表
        gbc.gridx = 0;
        gbc.gridy++;
        formPanel.add(new JLabel("排除ID列表 (逗号分隔):"), gbc);
        excludeIdsField = new JTextField(20);
        gbc.gridx = 1;
        formPanel.add(excludeIdsField, gbc);
    }
    
    /**
     * 刷新配置
     */
    private void refreshConfig() {
        try {
            if (configFileManager != null) {
                // 从配置文件读取
                configData = configFileManager.getTemplateConfig();
            } else if (client != null) {
                // 从API读取
                configData = client.getTemplateConfig();
            }
            
            updateFormValues();
        } catch (Exception e) {
            BurpExtender.stderr.println("刷新模板配置失败: " + e.getMessage());
            JOptionPane.showMessageDialog(this, "刷新模板配置失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * 更新表单值
     */
    private void updateFormValues() {
        // 将配置数据应用到表单中
        String severity = getStringValue(configData, "Severity");
        severityCombo.setSelectedItem(severity);
        
        String excludeSeverities = getStringValue(configData, "ExcludeSeverities");
        excludeSeveritiesCombo.setSelectedItem(excludeSeverities);
        
        String protocolTypes = getStringValue(configData, "ProtocolTypes");
        protocolTypesCombo.setSelectedItem(protocolTypes);
        
        String excludeProtocolTypes = getStringValue(configData, "ExcludeProtocolTypes");
        excludeProtocolTypesCombo.setSelectedItem(excludeProtocolTypes);
        
        List<String> authors = getListValue(configData, "Authors");
        authorsField.setText(String.join(",", authors));
        
        List<String> tags = getListValue(configData, "Tags");
        tagsField.setText(String.join(",", tags));
        
        List<String> excludeTags = getListValue(configData, "ExcludeTags");
        excludeTagsField.setText(String.join(",", excludeTags));
        
        List<String> includeTags = getListValue(configData, "IncludeTags");
        includeTagsField.setText(String.join(",", includeTags));
        
        List<String> ids = getListValue(configData, "IDs");
        idsField.setText(String.join(",", ids));
        
        List<String> excludeIds = getListValue(configData, "ExcludeIDs");
        excludeIdsField.setText(String.join(",", excludeIds));
    }
    
    /**
     * 保存配置
     */
    private void saveConfig() {
        try {
            // 获取表单值
            Map<String, Object> newConfig = new HashMap<>();
            
            newConfig.put("Severity", severityCombo.getSelectedItem().toString());
            newConfig.put("ExcludeSeverities", excludeSeveritiesCombo.getSelectedItem().toString());
            newConfig.put("ProtocolTypes", protocolTypesCombo.getSelectedItem().toString());
            newConfig.put("ExcludeProtocolTypes", excludeProtocolTypesCombo.getSelectedItem().toString());
            
            // 将逗号分隔的字符串转换为列表
            newConfig.put("Authors", splitToList(authorsField.getText()));
            newConfig.put("Tags", splitToList(tagsField.getText()));
            newConfig.put("ExcludeTags", splitToList(excludeTagsField.getText()));
            newConfig.put("IncludeTags", splitToList(includeTagsField.getText()));
            newConfig.put("IDs", splitToList(idsField.getText()));
            newConfig.put("ExcludeIDs", splitToList(excludeIdsField.getText()));
            
            boolean success = false;
            
            if (configFileManager != null) {
                // 保存到配置文件
                success = configFileManager.updateTemplateConfig(newConfig);
            } else if (client != null) {
                // 保存到API
                success = client.updateTemplateConfig(newConfig);
            }
            
            if (success) {
                JOptionPane.showMessageDialog(this, "模板配置保存成功!", "成功", JOptionPane.INFORMATION_MESSAGE);
                refreshConfig();
            } else {
                JOptionPane.showMessageDialog(this, "模板配置保存失败!", "错误", JOptionPane.ERROR_MESSAGE);
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("保存模板配置失败: " + e.getMessage());
            JOptionPane.showMessageDialog(this, "保存模板配置失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * 获取配置中的字符串值
     */
    private String getStringValue(Map<String, Object> config, String key) {
        if (config.containsKey(key)) {
            Object value = config.get(key);
            if (value instanceof String) {
                return (String) value;
            }
        }
        return "";
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