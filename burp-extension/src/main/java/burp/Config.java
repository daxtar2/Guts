package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * 系统全局配置
 */
public class Config {
    
    /**
     * Guts系统主机地址，默认为本地
     */
    public static String TARGET_HOST = "127.0.0.1";
    
    /**
     * Guts系统端口，默认为7777
     */
    public static int TARGET_PORT = 7777;
    
    /**
     * HTTP请求超时时间（毫秒）
     */
    public static final int TIMEOUT = 10000;
    
    /**
     * 请求间隔时间（毫秒）
     */
    public static int INTERVAL_TIME = 0;
    
    /**
     * 请求日志最大数量
     */
    public static int MAX_LOG_SIZE = 1000;
    
    /**
     * 是否转发所有请求（不应用过滤规则）
     */
    public static boolean FORWARD_ALL = false;
    
    /**
     * 是否自动开始转发
     */
    public static boolean AUTO_START = false;
    
    /**
     * 是否使用SSL安全验证
     */
    public static boolean SSL_INSECURE = true;
    
    /**
     * 包含域名列表
     */
    public static List<String> INCLUDE_DOMAINS = new ArrayList<>();
    
    /**
     * 排除域名列表
     */
    public static List<String> EXCLUDE_DOMAINS = new ArrayList<>();
    
    /**
     * 过滤文件后缀
     */
    public static List<String> FILTER_SUFFIXES = new ArrayList<>();

    /**
     * 请求计数器
     */
    public static int REQUEST_COUNT = 0;

    /**
     * 成功请求计数器
     */
    public static int SUCCESS_COUNT = 0;

    /**
     * 失败请求计数器
     */
    public static int FAIL_COUNT = 0;
    
    // 域名过滤正则缓存
    private static List<Pattern> includePatterns = new ArrayList<>();
    private static List<Pattern> excludePatterns = new ArrayList<>();
    
    /**
     * 获取完整的API地址
     */
    public static String getApiUrl() {
        return String.format("http://%s:%s/api", TARGET_HOST, TARGET_PORT);
    }
    
    /**
     * 判断URL是否应该被过滤
     */
    public static boolean shouldFilter(String url) {
        // 如果设置了转发所有请求，则不过滤
        if (FORWARD_ALL) {
            return false;
        }
        
        // 1. 检查域名白名单
        if (!INCLUDE_DOMAINS.isEmpty()) {
            boolean matched = false;
            for (Pattern pattern : includePatterns) {
                if (pattern.matcher(url).find()) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                return true; // 不在白名单中，需要过滤
            }
        }
        
        // 2. 检查域名黑名单
        if (!EXCLUDE_DOMAINS.isEmpty()) {
            for (Pattern pattern : excludePatterns) {
                if (pattern.matcher(url).find()) {
                    return true; // 在黑名单中，需要过滤
                }
            }
        }
        
        // 3. 检查文件后缀
        if (!FILTER_SUFFIXES.isEmpty()) {
            for (String suffix : FILTER_SUFFIXES) {
                if (url.endsWith(suffix)) {
                    return true; // 是被过滤的文件类型，需要过滤
                }
            }
        }
        
        return false; // 通过所有检查，不需要过滤
    }
    
    /**
     * 用于加载远程配置
     */
    @SuppressWarnings("unchecked")
    public static void loadRemoteConfig(GutsClient client) {
        try {
            // 获取过滤配置
            Map<String, Object> filterConfig = client.getFilterConfig();
            if (filterConfig != null && !filterConfig.isEmpty()) {
                BurpExtender.stdout.println("从远程加载过滤配置");
                
                // 解析域名白名单
                if (filterConfig.containsKey("IncludeDomains")) {
                    INCLUDE_DOMAINS.clear();
                    List<String> includeDomains = (List<String>) filterConfig.get("IncludeDomains");
                    if (includeDomains != null) {
                        INCLUDE_DOMAINS.addAll(includeDomains);
                        BurpExtender.stdout.println("已加载域名白名单: " + INCLUDE_DOMAINS.size() + " 条");
                    }
                }
                
                // 解析域名黑名单
                if (filterConfig.containsKey("ExcludeDomains")) {
                    EXCLUDE_DOMAINS.clear();
                    List<String> excludeDomains = (List<String>) filterConfig.get("ExcludeDomains");
                    if (excludeDomains != null) {
                        EXCLUDE_DOMAINS.addAll(excludeDomains);
                        BurpExtender.stdout.println("已加载域名黑名单: " + EXCLUDE_DOMAINS.size() + " 条");
                    }
                }
                
                // 解析文件后缀过滤
                if (filterConfig.containsKey("FilterSuffix")) {
                    FILTER_SUFFIXES.clear();
                    List<String> filterSuffixes = (List<String>) filterConfig.get("FilterSuffix");
                    if (filterSuffixes != null) {
                        FILTER_SUFFIXES.addAll(filterSuffixes);
                        BurpExtender.stdout.println("已加载文件后缀过滤: " + FILTER_SUFFIXES.size() + " 条");
                    }
                }
                
                // 解析SSL设置
                if (filterConfig.containsKey("SSL")) {
                    SSL_INSECURE = (Boolean) filterConfig.get("SSL");
                    BurpExtender.stdout.println("已加载SSL设置: " + SSL_INSECURE);
                }
                
                // 重新编译正则表达式
                compilePatterns();
            }
            
            // 获取扫描速率配置
            try {
                Map<String, Object> scanStats = client.getScanStats();
                if (scanStats != null && !scanStats.isEmpty()) {
                    BurpExtender.stdout.println("从远程加载扫描统计数据");
                    
                    // 更新相关配置
                    if (scanStats.containsKey("total")) {
                        int total = ((Number) scanStats.get("total")).intValue();
                        BurpExtender.stdout.println("已加载扫描结果总数: " + total);
                    }
                }
            } catch (Exception e) {
                BurpExtender.stderr.println("获取扫描统计数据失败: " + e.getMessage());
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("加载远程配置失败: " + e.getMessage());
        }
    }
    
    /**
     * 编译正则表达式
     */
    private static void compilePatterns() {
        // 编译包含域名正则
        includePatterns.clear();
        for (String domain : INCLUDE_DOMAINS) {
            try {
                Pattern pattern = Pattern.compile(domain, Pattern.CASE_INSENSITIVE);
                includePatterns.add(pattern);
            } catch (Exception e) {
                BurpExtender.stderr.println("编译包含域名正则失败: " + domain + " - " + e.getMessage());
            }
        }
        
        // 编译排除域名正则
        excludePatterns.clear();
        for (String domain : EXCLUDE_DOMAINS) {
            try {
                Pattern pattern = Pattern.compile(domain, Pattern.CASE_INSENSITIVE);
                excludePatterns.add(pattern);
            } catch (Exception e) {
                BurpExtender.stderr.println("编译排除域名正则失败: " + domain + " - " + e.getMessage());
            }
        }
    }
    
    /**
     * 重置计数器
     */
    public static void resetCounters() {
        REQUEST_COUNT = 0;
        SUCCESS_COUNT = 0;
        FAIL_COUNT = 0;
    }
} 