package burp;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;

/**
 * Guts服务客户端
 */
public class GutsClient {
    
    // 目标主机和端口
    private String targetHost;
    private int targetPort;
    
    // Gson实例
    private final Gson gson = new Gson();
    
    /**
     * 构造函数
     */
    public GutsClient(String targetHost, int targetPort) {
        this.targetHost = targetHost;
        this.targetPort = targetPort;
    }
    
    /**
     * 转发HTTP请求到Guts系统
     */
    public Map<String, String> forwardRequest(IHttpRequestResponse requestResponse) throws IOException, InterruptedException {
        Map<String, String> result = new HashMap<>();
        
        // 构建请求URL
        String targetUrl = String.format("http://%s:%s/api/scan/passive", 
                Config.TARGET_HOST, Config.TARGET_PORT);
        
        // 获取原始请求信息
        byte[] requestData = requestResponse.getRequest();
        IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(requestResponse);
        IHttpService httpService = requestResponse.getHttpService();
        URL url = requestInfo.getUrl();
        
        // 提取请求头
        List<String> headers = requestInfo.getHeaders();
        String method = requestInfo.getMethod();
        
        // 提取请求体
        int bodyOffset = requestInfo.getBodyOffset();
        String body = "";
        if (requestData.length > bodyOffset) {
            body = new String(Arrays.copyOfRange(requestData, bodyOffset, requestData.length), StandardCharsets.UTF_8);
        }
        
        // 构建JSON请求体
        JsonObject requestJson = new JsonObject();
        requestJson.addProperty("url", url.toString());
        requestJson.addProperty("host", url.getHost());
        requestJson.addProperty("method", method);
        
        // 添加请求头
        JsonObject headersJson = new JsonObject();
        for (int i = 1; i < headers.size(); i++) { // 跳过第一行（请求行）
            String header = headers.get(i);
            int colonIndex = header.indexOf(":");
            if (colonIndex > 0) {
                String name = header.substring(0, colonIndex).trim();
                String value = header.substring(colonIndex + 1).trim();
                headersJson.addProperty(name, value);
            }
        }
        requestJson.add("headers", headersJson);
        
        // 添加请求体
        requestJson.addProperty("body", body);
        
        // 添加协议
        requestJson.addProperty("scheme", url.getProtocol());
        
        // 获取响应数据，如果有
        byte[] responseData = requestResponse.getResponse();
        if (responseData != null) {
            IResponseInfo responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(responseData);
            
            // 提取响应头
            List<String> responseHeaders = responseInfo.getHeaders();
            JsonObject responseHeadersJson = new JsonObject();
            for (int i = 1; i < responseHeaders.size(); i++) { // 跳过第一行（状态行）
                String header = responseHeaders.get(i);
                int colonIndex = header.indexOf(":");
                if (colonIndex > 0) {
                    String name = header.substring(0, colonIndex).trim();
                    String value = header.substring(colonIndex + 1).trim();
                    responseHeadersJson.addProperty(name, value);
                }
            }
            
            // 提取响应体
            int responseBodyOffset = responseInfo.getBodyOffset();
            String responseBody = "";
            if (responseData.length > responseBodyOffset) {
                responseBody = new String(Arrays.copyOfRange(responseData, responseBodyOffset, responseData.length), StandardCharsets.UTF_8);
            }
            
            // 添加响应信息
            requestJson.add("responseHeader", responseHeadersJson);
            requestJson.addProperty("responseBody", responseBody);
            requestJson.addProperty("statusCode", responseInfo.getStatusCode());
        }
        
        // 创建HTTP客户端并设置超时
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Config.TIMEOUT)
                .setSocketTimeout(Config.TIMEOUT)
                .build();
        
        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            
            // 构建POST请求
            HttpPost httpPost = new HttpPost(targetUrl);
            httpPost.setHeader("Content-Type", "application/json");
            String jsonBody = gson.toJson(requestJson);
            
            // 日志记录请求内容
            BurpExtender.stdout.println("转发请求到Guts服务: " + url.toString());
            BurpExtender.stdout.println("请求JSON大小: " + jsonBody.length() + " 字节");
            
            httpPost.setEntity(new StringEntity(jsonBody, ContentType.APPLICATION_JSON));
            
            // 执行请求
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                HttpEntity entity = response.getEntity();
                String responseBody = EntityUtils.toString(entity);
                
                int statusCode = response.getStatusLine().getStatusCode();
                result.put("status", String.valueOf(statusCode));
                result.put("result", responseBody);
                result.put("header", Arrays.toString(response.getAllHeaders()));
                result.put("proxyHost", Config.TARGET_HOST + ":" + Config.TARGET_PORT);
                
                // 解析响应内容
                try {
                    JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);
                    if (jsonResponse.has("status")) {
                        String status = jsonResponse.get("status").getAsString();
                        result.put("scanStatus", status);
                        
                        if (jsonResponse.has("message")) {
                            result.put("message", jsonResponse.get("message").getAsString());
                        }
                        
                        if (status.equals("success") && jsonResponse.has("data")) {
                            result.put("hasData", "true");
                            // 可以在这里添加更多的数据解析逻辑
                        }
                    }
                } catch (Exception e) {
                    BurpExtender.stderr.println("解析响应JSON失败: " + e.getMessage());
                }
                
                BurpExtender.stdout.println("Guts服务响应: " + statusCode + " - " + 
                        (statusCode == 200 ? "成功" : "失败"));
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("转发请求失败: " + e.getMessage());
            result.put("status", "ERROR");
            result.put("result", e.getMessage());
            result.put("header", "");
            result.put("proxyHost", Config.TARGET_HOST + ":" + Config.TARGET_PORT);
        }
        
        // 如果配置了请求间隔，则等待
        if (Config.INTERVAL_TIME > 0) {
            Thread.sleep(Config.INTERVAL_TIME);
        }
        
        return result;
    }
    
    /**
     * 获取所有扫描结果
     */
    public List<Map<String, Object>> getScanResults(int page, int pageSize) throws IOException {
        List<Map<String, Object>> results = new ArrayList<>();
        
        // 构建请求URL
        String targetUrl = String.format("http://%s:%s/api/scan/results?page=%d&pageSize=%d", 
                Config.TARGET_HOST, Config.TARGET_PORT, page, pageSize);
        
        // 创建HTTP客户端
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Config.TIMEOUT)
                .setSocketTimeout(Config.TIMEOUT)
                .build();
        
        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            
            // 构建GET请求
            HttpGet httpGet = new HttpGet(targetUrl);
            
            // 执行请求
            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                HttpEntity entity = response.getEntity();
                String responseBody = EntityUtils.toString(entity);
                
                // 解析响应
                JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);
                if (jsonResponse.has("status") && "success".equals(jsonResponse.get("status").getAsString())) {
                    JsonObject data = jsonResponse.getAsJsonObject("data");
                    if (data.has("results")) {
                        JsonArray resultsArray = data.getAsJsonArray("results");
                        Type resultType = new TypeToken<List<Map<String, Object>>>(){}.getType();
                        results = gson.fromJson(resultsArray, resultType);
                        BurpExtender.stdout.println("获取到 " + results.size() + " 条扫描结果");
                    }
                }
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("获取扫描结果失败: " + e.getMessage());
        }
        
        return results;
    }
    
    /**
     * 获取扫描结果统计
     */
    public Map<String, Object> getScanStats() throws IOException {
        Map<String, Object> stats = new HashMap<>();
        
        // 构建请求URL
        String targetUrl = String.format("http://%s:%s/api/scan/stats", 
                Config.TARGET_HOST, Config.TARGET_PORT);
        
        // 创建HTTP客户端
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Config.TIMEOUT)
                .setSocketTimeout(Config.TIMEOUT)
                .build();
        
        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            
            // 构建GET请求
            HttpGet httpGet = new HttpGet(targetUrl);
            
            // 执行请求
            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                HttpEntity entity = response.getEntity();
                String responseBody = EntityUtils.toString(entity);
                
                // 解析响应
                JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);
                if (jsonResponse.has("status") && "success".equals(jsonResponse.get("status").getAsString())) {
                    JsonObject data = jsonResponse.getAsJsonObject("data");
                    
                    // 总数
                    if (data.has("total")) {
                        stats.put("total", data.get("total").getAsInt());
                    }
                    
                    // 按严重程度统计
                    if (data.has("severity")) {
                        JsonObject severity = data.getAsJsonObject("severity");
                        for (String key : severity.keySet()) {
                            stats.put("severity_" + key, severity.get(key).getAsInt());
                        }
                    }
                    
                    // 其他统计数据
                    if (data.has("lastScanned")) {
                        stats.put("lastScanned", data.get("lastScanned").getAsString());
                    }
                }
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("获取扫描统计失败: " + e.getMessage());
        }
        
        return stats;
    }
    
    /**
     * 获取过滤配置
     */
    public Map<String, Object> getFilterConfig() throws Exception {
        String url = String.format("http://%s:%d/api/filter", Config.TARGET_HOST, Config.TARGET_PORT);
        
        // 创建 HttpClient 并设置超时
        HttpClient client = HttpClients.custom()
            .setDefaultRequestConfig(RequestConfig.custom()
                .setConnectTimeout(10000)
                .setSocketTimeout(10000)
                .build())
            .build();
        
        // 创建 GET 请求
        HttpGet request = new HttpGet(url);
        
        // 执行请求
        HttpResponse response = client.execute(request);
        int statusCode = response.getStatusLine().getStatusCode();
        
        // 读取响应
        HttpEntity entity = response.getEntity();
        String responseBody = EntityUtils.toString(entity);
        
        if (statusCode != 200) {
            BurpExtender.stderr.println("获取过滤配置失败: " + responseBody);
            throw new Exception("获取过滤配置失败: HTTP " + statusCode);
        }
        
        // 解析JSON响应
        Map<String, Object> result = new HashMap<>();
        JsonNode rootNode = new ObjectMapper().readTree(responseBody);
        
        // 检查响应状态
        if (!rootNode.get("status").asBoolean()) {
            throw new Exception("API返回错误: " + rootNode.get("msg").asText());
        }
        
        // 获取数据
        JsonNode dataNode = rootNode.get("data");
        
        if (dataNode.has("SSL")) {
            result.put("SSL", dataNode.get("SSL").asBoolean());
        }
        
        if (dataNode.has("IncludeDomains")) {
            List<String> includeDomains = new ArrayList<>();
            JsonNode domainsNode = dataNode.get("IncludeDomains");
            if (domainsNode.isArray()) {
                for (JsonNode node : domainsNode) {
                    includeDomains.add(node.asText());
                }
            }
            result.put("IncludeDomains", includeDomains);
        }
        
        if (dataNode.has("ExcludeDomains")) {
            List<String> excludeDomains = new ArrayList<>();
            JsonNode domainsNode = dataNode.get("ExcludeDomains");
            if (domainsNode.isArray()) {
                for (JsonNode node : domainsNode) {
                    excludeDomains.add(node.asText());
                }
            }
            result.put("ExcludeDomains", excludeDomains);
        }
        
        if (dataNode.has("FilterSuffix")) {
            List<String> filterSuffix = new ArrayList<>();
            JsonNode suffixNode = dataNode.get("FilterSuffix");
            if (suffixNode.isArray()) {
                for (JsonNode node : suffixNode) {
                    filterSuffix.add(node.asText());
                }
            }
            result.put("FilterSuffix", filterSuffix);
        }
        
        return result;
    }
    
    /**
     * 更新过滤配置
     */
    public boolean updateFilterConfig(Map<String, Object> config) throws Exception {
        String url = String.format("http://%s:%d/api/filter", Config.TARGET_HOST, Config.TARGET_PORT);
        
        // 创建 HttpClient 并设置超时
        HttpClient client = HttpClients.custom()
            .setDefaultRequestConfig(RequestConfig.custom()
                .setConnectTimeout(10000)
                .setSocketTimeout(10000)
                .build())
            .build();
        
        // 创建 POST 请求
        HttpPost request = new HttpPost(url);
        request.setHeader("Content-Type", "application/json");
        
        // 将配置转换为 JSON
        ObjectMapper mapper = new ObjectMapper();
        String jsonBody = mapper.writeValueAsString(config);
        
        request.setEntity(new StringEntity(jsonBody));
        
        // 执行请求
        HttpResponse response = client.execute(request);
        int statusCode = response.getStatusLine().getStatusCode();
        
        // 读取响应
        HttpEntity entity = response.getEntity();
        String responseBody = EntityUtils.toString(entity);
        
        if (statusCode != 200) {
            BurpExtender.stderr.println("更新过滤配置失败: " + responseBody);
            throw new Exception("更新过滤配置失败: HTTP " + statusCode);
        }
        
        // 解析JSON响应
        JsonNode rootNode = mapper.readTree(responseBody);
        
        // 检查响应状态
        boolean success = rootNode.get("status").asBoolean();
        String message = rootNode.get("msg").asText();
        
        if (!success) {
            BurpExtender.stderr.println("更新过滤配置失败: " + message);
        } else {
            BurpExtender.stdout.println("更新过滤配置成功: " + message);
        }
        
        return success;
    }
    
    /**
     * 获取模板配置
     */
    public Map<String, Object> getTemplateConfig() throws Exception {
        String url = String.format("http://%s:%d/api/template", Config.TARGET_HOST, Config.TARGET_PORT);
        
        // 创建 HttpClient 并设置超时
        HttpClient client = HttpClients.custom()
            .setDefaultRequestConfig(RequestConfig.custom()
                .setConnectTimeout(10000)
                .setSocketTimeout(10000)
                .build())
            .build();
        
        // 创建 GET 请求
        HttpGet request = new HttpGet(url);
        
        // 执行请求
        HttpResponse response = client.execute(request);
        int statusCode = response.getStatusLine().getStatusCode();
        
        // 读取响应
        HttpEntity entity = response.getEntity();
        String responseBody = EntityUtils.toString(entity);
        
        if (statusCode != 200) {
            BurpExtender.stderr.println("获取模板配置失败: " + responseBody);
            throw new Exception("获取模板配置失败: HTTP " + statusCode);
        }
        
        // 解析JSON响应
        Map<String, Object> result = new HashMap<>();
        JsonNode rootNode = new ObjectMapper().readTree(responseBody);
        
        // 检查响应状态
        if (!rootNode.get("status").asBoolean()) {
            throw new Exception("API返回错误: " + rootNode.get("msg").asText());
        }
        
        // 获取数据
        JsonNode dataNode = rootNode.get("data");
        
        // 处理字符串字段
        if (dataNode.has("Severity")) {
            result.put("Severity", dataNode.get("Severity").asText());
        }
        
        if (dataNode.has("ExcludeSeverities")) {
            result.put("ExcludeSeverities", dataNode.get("ExcludeSeverities").asText());
        }
        
        if (dataNode.has("ProtocolTypes")) {
            result.put("ProtocolTypes", dataNode.get("ProtocolTypes").asText());
        }
        
        if (dataNode.has("ExcludeProtocolTypes")) {
            result.put("ExcludeProtocolTypes", dataNode.get("ExcludeProtocolTypes").asText());
        }
        
        // 处理数组字段
        processArrayField(dataNode, result, "Authors");
        processArrayField(dataNode, result, "Tags");
        processArrayField(dataNode, result, "ExcludeTags");
        processArrayField(dataNode, result, "IncludeTags");
        processArrayField(dataNode, result, "IDs");
        processArrayField(dataNode, result, "ExcludeIDs");
        
        return result;
    }
    
    /**
     * 处理数组字段
     */
    private void processArrayField(JsonNode dataNode, Map<String, Object> result, String fieldName) {
        if (dataNode.has(fieldName)) {
            List<String> list = new ArrayList<>();
            JsonNode arrayNode = dataNode.get(fieldName);
            if (arrayNode.isArray()) {
                for (JsonNode node : arrayNode) {
                    list.add(node.asText());
                }
            }
            result.put(fieldName, list);
        }
    }
    
    /**
     * 更新模板配置
     */
    public boolean updateTemplateConfig(Map<String, Object> config) throws Exception {
        String url = String.format("http://%s:%d/api/template", Config.TARGET_HOST, Config.TARGET_PORT);
        
        // 创建 HttpClient 并设置超时
        HttpClient client = HttpClients.custom()
            .setDefaultRequestConfig(RequestConfig.custom()
                .setConnectTimeout(10000)
                .setSocketTimeout(10000)
                .build())
            .build();
        
        // 创建 POST 请求
        HttpPost request = new HttpPost(url);
        request.setHeader("Content-Type", "application/json");
        
        // 某些字段可能需要特殊处理
        Map<String, Object> requestData = new HashMap<>(config);
        
        // 将配置转换为 JSON
        ObjectMapper mapper = new ObjectMapper();
        String jsonBody = mapper.writeValueAsString(requestData);
        
        request.setEntity(new StringEntity(jsonBody));
        
        // 执行请求
        HttpResponse response = client.execute(request);
        int statusCode = response.getStatusLine().getStatusCode();
        
        // 读取响应
        HttpEntity entity = response.getEntity();
        String responseBody = EntityUtils.toString(entity);
        
        if (statusCode != 200) {
            BurpExtender.stderr.println("更新模板配置失败: " + responseBody);
            throw new Exception("更新模板配置失败: HTTP " + statusCode);
        }
        
        // 解析JSON响应
        JsonNode rootNode = mapper.readTree(responseBody);
        
        // 检查响应状态
        boolean success = rootNode.get("status").asBoolean();
        String message = rootNode.get("msg").asText();
        
        if (!success) {
            BurpExtender.stderr.println("更新模板配置失败: " + message);
        } else {
            BurpExtender.stdout.println("更新模板配置成功: " + message);
        }
        
        return success;
    }
    
    /**
     * 处理扫描请求
     */
    public void processScanRequest(int id, String url, String host, int port, String protocol, byte[] request, byte[] response) {
        try {
            // 构建URL
            String targetUrl = String.format("http://%s:%d/api/scan", targetHost, targetPort);
            
            // 创建 HttpClient 并设置超时
            HttpClient client = HttpClientBuilder.create()
                .setDefaultRequestConfig(RequestConfig.custom()
                    .setConnectTimeout(10000)
                    .setSocketTimeout(10000)
                    .build())
                .build();
            
            // 创建 POST 请求
            HttpPost httpPost = new HttpPost(targetUrl);
            httpPost.setHeader("Content-Type", "application/json");
            
            // 构建请求体
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("id", id);
            requestBody.put("url", url);
            requestBody.put("host", host);
            requestBody.put("port", port);
            requestBody.put("protocol", protocol);
            requestBody.put("request", Base64.getEncoder().encodeToString(request));
            requestBody.put("response", Base64.getEncoder().encodeToString(response));
            
            // 转换为JSON
            String jsonBody = gson.toJson(requestBody);
            
            httpPost.setEntity(new StringEntity(jsonBody, ContentType.APPLICATION_JSON));
            
            // 执行请求
            HttpResponse apiResponse = client.execute(httpPost);
            int statusCode = apiResponse.getStatusLine().getStatusCode();
            
            // 读取响应
            HttpEntity entity = apiResponse.getEntity();
            String responseBody = EntityUtils.toString(entity);
            
            if (statusCode != 200) {
                BurpExtender.stderr.println("扫描请求失败 [" + id + "]: HTTP " + statusCode);
                BurpExtender.stderr.println("响应: " + responseBody);
                return;
            }
            
            // 解析JSON响应
            JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);
            
            // 检查响应状态
            boolean success = jsonResponse.has("status") && jsonResponse.get("status").getAsBoolean();
            String message = jsonResponse.has("msg") ? jsonResponse.get("msg").getAsString() : "无消息";
            
            if (success) {
                BurpExtender.stdout.println("扫描请求成功 [" + id + "]: " + message);
            } else {
                BurpExtender.stderr.println("扫描请求失败 [" + id + "]: " + message);
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("处理扫描请求异常 [" + id + "]: " + e.getMessage());
        }
    }

    /**
     * 测试连接
     */
    public boolean testConnection(String host, int port) throws Exception {
        String url = String.format("http://%s:%d/api/ping", host, port);
        
        // 创建 HttpClient 并设置超时
        HttpClient client = HttpClientBuilder.create()
            .setDefaultRequestConfig(RequestConfig.custom()
                .setConnectTimeout(5000)
                .setSocketTimeout(5000)
                .build())
            .build();
        
        // 创建 GET 请求
        HttpGet request = new HttpGet(url);
        
        try {
            // 执行请求
            HttpResponse response = client.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            
            // 读取响应
            HttpEntity entity = response.getEntity();
            String responseBody = EntityUtils.toString(entity);
            
            if (statusCode != 200) {
                BurpExtender.stderr.println("连接测试失败: HTTP " + statusCode);
                return false;
            }
            
            // 解析JSON响应
            JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);
            
            // 检查响应状态
            if (!jsonResponse.has("status") || !jsonResponse.get("status").getAsBoolean()) {
                BurpExtender.stderr.println("连接测试失败: " + responseBody);
                return false;
            }
            
            BurpExtender.stdout.println("连接测试成功: " + responseBody);
            return true;
        } catch (Exception e) {
            BurpExtender.stderr.println("连接测试异常: " + e.getMessage());
            throw e;
        }
    }

    /**
     * 更新连接设置
     */
    public void updateConnection(String host, int port) {
        this.targetHost = host;
        this.targetPort = port;
        BurpExtender.stdout.println("连接设置已更新: " + host + ":" + port);
    }
} 