package burp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 配置文件管理器 - 直接读写config.yaml文件
 */
public class ConfigFileManager {
    
    private static final String DEFAULT_CONFIG_FILE_PATH = "../config/config.yaml";
    private final String configFilePath;
    private final ObjectMapper yamlMapper;
    private ObjectNode rootNode;
    
    /**
     * 构造函数 - 使用默认路径
     */
    public ConfigFileManager() {
        this(DEFAULT_CONFIG_FILE_PATH);
    }
    
    /**
     * 构造函数 - 使用自定义路径
     */
    public ConfigFileManager(String configFilePath) {
        this.configFilePath = configFilePath;
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
        loadConfig();
    }
    
    /**
     * 加载配置文件
     */
    private void loadConfig() {
        try {
            File configFile = new File(configFilePath);
            if (configFile.exists()) {
                rootNode = (ObjectNode) yamlMapper.readTree(configFile);
                BurpExtender.stdout.println("成功加载配置文件: " + configFile.getAbsolutePath());
            } else {
                BurpExtender.stderr.println("配置文件不存在: " + configFile.getAbsolutePath());
                rootNode = yamlMapper.createObjectNode();
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("加载配置文件失败: " + e.getMessage());
            rootNode = yamlMapper.createObjectNode();
        }
    }
    
    /**
     * 保存配置文件
     */
    private boolean saveConfig() {
        try {
            File configFile = new File(configFilePath);
            yamlMapper.writeValue(configFile, rootNode);
            BurpExtender.stdout.println("成功保存配置文件: " + configFile.getAbsolutePath());
            return true;
        } catch (Exception e) {
            BurpExtender.stderr.println("保存配置文件失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 获取过滤配置
     */
    public Map<String, Object> getFilterConfig() {
        Map<String, Object> config = new HashMap<>();
        try {
            if (rootNode.has("mitmproxy")) {
                ObjectNode mitmNode = (ObjectNode) rootNode.get("mitmproxy");
                
                // 获取SSL配置
                if (mitmNode.has("sslinsecure")) {
                    config.put("SSL", mitmNode.get("sslinsecure").asBoolean());
                }
                
                // 获取包含域名
                if (mitmNode.has("includedomain")) {
                    List<String> includeDomains = new ArrayList<>();
                    ArrayNode includeNode = (ArrayNode) mitmNode.get("includedomain");
                    for (int i = 0; i < includeNode.size(); i++) {
                        includeDomains.add(includeNode.get(i).asText());
                    }
                    config.put("IncludeDomains", includeDomains);
                }
                
                // 获取排除域名
                if (mitmNode.has("excludedomain")) {
                    List<String> excludeDomains = new ArrayList<>();
                    ArrayNode excludeNode = (ArrayNode) mitmNode.get("excludedomain");
                    for (int i = 0; i < excludeNode.size(); i++) {
                        excludeDomains.add(excludeNode.get(i).asText());
                    }
                    config.put("ExcludeDomains", excludeDomains);
                }
                
                // 获取过滤后缀
                if (mitmNode.has("filtersuffix")) {
                    List<String> filterSuffix = new ArrayList<>();
                    ArrayNode suffixNode = (ArrayNode) mitmNode.get("filtersuffix");
                    for (int i = 0; i < suffixNode.size(); i++) {
                        filterSuffix.add(suffixNode.get(i).asText());
                    }
                    config.put("FilterSuffix", filterSuffix);
                }
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("获取过滤配置失败: " + e.getMessage());
        }
        return config;
    }
    
    /**
     * 更新过滤配置
     */
    public boolean updateFilterConfig(Map<String, Object> config) {
        try {
            if (!rootNode.has("mitmproxy")) {
                rootNode.set("mitmproxy", yamlMapper.createObjectNode());
            }
            ObjectNode mitmNode = (ObjectNode) rootNode.get("mitmproxy");
            
            // 更新SSL配置
            if (config.containsKey("SSL")) {
                mitmNode.put("sslinsecure", (Boolean) config.get("SSL"));
            }
            
            // 更新包含域名
            if (config.containsKey("IncludeDomains")) {
                @SuppressWarnings("unchecked")
                List<String> includeDomains = (List<String>) config.get("IncludeDomains");
                ArrayNode includeNode = yamlMapper.createArrayNode();
                for (String domain : includeDomains) {
                    includeNode.add(domain);
                }
                mitmNode.set("includedomain", includeNode);
            }
            
            // 更新排除域名
            if (config.containsKey("ExcludeDomains")) {
                @SuppressWarnings("unchecked")
                List<String> excludeDomains = (List<String>) config.get("ExcludeDomains");
                ArrayNode excludeNode = yamlMapper.createArrayNode();
                for (String domain : excludeDomains) {
                    excludeNode.add(domain);
                }
                mitmNode.set("excludedomain", excludeNode);
            }
            
            // 更新过滤后缀
            if (config.containsKey("FilterSuffix")) {
                @SuppressWarnings("unchecked")
                List<String> filterSuffix = (List<String>) config.get("FilterSuffix");
                ArrayNode suffixNode = yamlMapper.createArrayNode();
                for (String suffix : filterSuffix) {
                    suffixNode.add(suffix);
                }
                mitmNode.set("filtersuffix", suffixNode);
            }
            
            // 保存配置
            return saveConfig();
        } catch (Exception e) {
            BurpExtender.stderr.println("更新过滤配置失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 获取模板配置
     */
    public Map<String, Object> getTemplateConfig() {
        Map<String, Object> config = new HashMap<>();
        try {
            if (rootNode.has("templatefilters")) {
                ObjectNode templateNode = (ObjectNode) rootNode.get("templatefilters");
                
                // 获取字符串配置
                if (templateNode.has("severity")) {
                    config.put("Severity", templateNode.get("severity").asText());
                }
                
                if (templateNode.has("excludeseverities")) {
                    config.put("ExcludeSeverities", templateNode.get("excludeseverities").asText());
                }
                
                if (templateNode.has("protocoltypes")) {
                    config.put("ProtocolTypes", templateNode.get("protocoltypes").asText());
                }
                
                if (templateNode.has("excludeprotocoltypes")) {
                    config.put("ExcludeProtocolTypes", templateNode.get("excludeprotocoltypes").asText());
                }
                
                // 获取数组配置
                for (String fieldName : new String[]{"authors", "tags", "excludetags", "includetags", "ids", "excludeids"}) {
                    if (templateNode.has(fieldName)) {
                        List<String> list = new ArrayList<>();
                        ArrayNode arrayNode = (ArrayNode) templateNode.get(fieldName);
                        for (int i = 0; i < arrayNode.size(); i++) {
                            list.add(arrayNode.get(i).asText());
                        }
                        
                        // 转换字段名为驼峰命名
                        String key = fieldName;
                        if (fieldName.equals("excludetags")) {
                            key = "ExcludeTags";
                        } else if (fieldName.equals("includetags")) {
                            key = "IncludeTags";
                        } else if (fieldName.equals("ids")) {
                            key = "IDs";
                        } else if (fieldName.equals("excludeids")) {
                            key = "ExcludeIDs";
                        } else if (fieldName.equals("authors")) {
                            key = "Authors";
                        } else if (fieldName.equals("tags")) {
                            key = "Tags";
                        }
                        
                        config.put(key, list);
                    }
                }
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("获取模板配置失败: " + e.getMessage());
        }
        return config;
    }
    
    /**
     * 更新模板配置
     */
    public boolean updateTemplateConfig(Map<String, Object> config) {
        try {
            if (!rootNode.has("templatefilters")) {
                rootNode.set("templatefilters", yamlMapper.createObjectNode());
            }
            ObjectNode templateNode = (ObjectNode) rootNode.get("templatefilters");
            
            // 更新字符串配置
            updateStringValue(templateNode, config, "Severity", "severity");
            updateStringValue(templateNode, config, "ExcludeSeverities", "excludeseverities");
            updateStringValue(templateNode, config, "ProtocolTypes", "protocoltypes");
            updateStringValue(templateNode, config, "ExcludeProtocolTypes", "excludeprotocoltypes");
            
            // 更新数组配置
            updateArrayValue(templateNode, config, "Authors", "authors");
            updateArrayValue(templateNode, config, "Tags", "tags");
            updateArrayValue(templateNode, config, "ExcludeTags", "excludetags");
            updateArrayValue(templateNode, config, "IncludeTags", "includetags");
            updateArrayValue(templateNode, config, "IDs", "ids");
            updateArrayValue(templateNode, config, "ExcludeIDs", "excludeids");
            
            // 保存配置
            return saveConfig();
        } catch (Exception e) {
            BurpExtender.stderr.println("更新模板配置失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 更新字符串值
     */
    private void updateStringValue(ObjectNode node, Map<String, Object> config, String sourceKey, String targetKey) {
        if (config.containsKey(sourceKey)) {
            Object value = config.get(sourceKey);
            if (value instanceof String) {
                node.put(targetKey, (String) value);
            }
        }
    }
    
    /**
     * 更新数组值
     */
    @SuppressWarnings("unchecked")
    private void updateArrayValue(ObjectNode node, Map<String, Object> config, String sourceKey, String targetKey) {
        if (config.containsKey(sourceKey)) {
            Object value = config.get(sourceKey);
            if (value instanceof List) {
                List<String> list = (List<String>) value;
                ArrayNode arrayNode = yamlMapper.createArrayNode();
                for (String item : list) {
                    arrayNode.add(item);
                }
                node.set(targetKey, arrayNode);
            }
        }
    }
    
    /**
     * 获取路径模糊测试配置
     */
    public Map<String, Object> getPathFuzzConfig() {
        Map<String, Object> config = new HashMap<>();
        try {
            if (rootNode.has("path_fuzz")) {
                ObjectNode fuzzNode = (ObjectNode) rootNode.get("path_fuzz");
                
                // 获取启用状态
                if (fuzzNode.has("enabled")) {
                    config.put("Enabled", fuzzNode.get("enabled").asBoolean());
                }
                
                // 获取路径列表
                if (fuzzNode.has("paths")) {
                    List<String> paths = new ArrayList<>();
                    ArrayNode pathsNode = (ArrayNode) fuzzNode.get("paths");
                    for (int i = 0; i < pathsNode.size(); i++) {
                        paths.add(pathsNode.get(i).asText());
                    }
                    config.put("Paths", paths);
                }
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("获取路径模糊测试配置失败: " + e.getMessage());
        }
        return config;
    }
    
    /**
     * 更新路径模糊测试配置
     */
    public boolean updatePathFuzzConfig(Map<String, Object> config) {
        try {
            if (!rootNode.has("path_fuzz")) {
                rootNode.set("path_fuzz", yamlMapper.createObjectNode());
            }
            ObjectNode fuzzNode = (ObjectNode) rootNode.get("path_fuzz");
            
            // 更新启用状态
            if (config.containsKey("Enabled")) {
                fuzzNode.put("enabled", (Boolean) config.get("Enabled"));
            }
            
            // 更新路径列表
            if (config.containsKey("Paths")) {
                @SuppressWarnings("unchecked")
                List<String> paths = (List<String>) config.get("Paths");
                ArrayNode pathsNode = yamlMapper.createArrayNode();
                for (String path : paths) {
                    pathsNode.add(path);
                }
                fuzzNode.set("paths", pathsNode);
            }
            
            // 保存配置
            return saveConfig();
        } catch (Exception e) {
            BurpExtender.stderr.println("更新路径模糊测试配置失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 获取配置文件路径
     */
    public String getConfigFilePath() {
        return configFilePath;
    }
} 