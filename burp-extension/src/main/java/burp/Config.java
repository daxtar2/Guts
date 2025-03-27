package burp;

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
    public static String TARGET_PORT = "7777";
    
    /**
     * HTTP请求超时时间（毫秒）
     */
    public static int TIMEOUT = 10000;
    
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
    public static String[] INCLUDE_DOMAINS = {};
    
    /**
     * 排除域名列表
     */
    public static String[] EXCLUDE_DOMAINS = {};
    
    /**
     * 过滤文件后缀
     */
    public static String[] FILTER_SUFFIX = {
            ".css", ".js", ".jpg", ".jpeg", ".gif", ".png", ".bmp", ".ico", ".svg",
            ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".avi", ".wmv", ".flv",
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".zip", ".rar",
            ".7z", ".tar", ".gz", ".tgz", ".bz2"
    };

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
    
    /**
     * 获取完整的API地址
     */
    public static String getApiUrl() {
        return String.format("http://%s:%s/api", TARGET_HOST, TARGET_PORT);
    }
    
    /**
     * 判断URL是否应该被过滤（基于文件后缀和域名规则）
     */
    public static boolean shouldFilter(String url) {
        if (FORWARD_ALL) {
            return false; // 不过滤任何请求
        }
        
        // 检查文件后缀
        for (String suffix : FILTER_SUFFIX) {
            if (url.toLowerCase().endsWith(suffix.toLowerCase())) {
                return true; // 过滤掉静态资源
            }
        }
        
        // 检查域名包含规则
        if (INCLUDE_DOMAINS.length > 0) {
            boolean included = false;
            for (String domain : INCLUDE_DOMAINS) {
                if (domain.trim().isEmpty()) {
                    continue;
                }
                if (url.contains(domain.trim())) {
                    included = true;
                    break;
                }
            }
            if (!included) {
                return true; // 不在包含列表中
            }
        }
        
        // 检查域名排除规则
        if (EXCLUDE_DOMAINS.length > 0) {
            for (String domain : EXCLUDE_DOMAINS) {
                if (domain.trim().isEmpty()) {
                    continue;
                }
                if (url.contains(domain.trim())) {
                    return true; // 在排除列表中
                }
            }
        }
        
        return false; // 不需要过滤
    }
    
    /**
     * 用于加载远程配置
     */
    public static void loadRemoteConfig(GutsClient client) {
        try {
            // 获取过滤配置
            var filterConfig = client.getFilterConfig();
            if (!filterConfig.isEmpty()) {
                // TODO: 将JSON数组转换为字符串数组
                // INCLUDE_DOMAINS = convertJsonArrayToStringArray(filterConfig.get("includedomain"));
                // EXCLUDE_DOMAINS = convertJsonArrayToStringArray(filterConfig.get("excludedomain"));
                // FILTER_SUFFIX = convertJsonArrayToStringArray(filterConfig.get("filtersuffix"));
                
                if (filterConfig.containsKey("sslinsecure")) {
                    SSL_INSECURE = (Boolean)filterConfig.get("sslinsecure");
                }
            }
            
            // 获取扫描速率配置
            var scanRateConfig = client.getScanRateConfig();
            if (!scanRateConfig.isEmpty()) {
                if (scanRateConfig.containsKey("globalrate")) {
                    // 可以设置请求间隔等参数
                }
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("Error loading remote config: " + e.getMessage());
        }
    }
} 