package burp;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Guts系统通信客户端
 */
public class GutsClient {
    
    private final Gson gson = new Gson();
    
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
        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
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
            IResponseInfo responseInfo = BurpExtender.helpers.analyzeResponse(responseData);
            
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
            httpPost.setEntity(new StringEntity(gson.toJson(requestJson), ContentType.APPLICATION_JSON));
            
            // 执行请求
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                HttpEntity entity = response.getEntity();
                String responseBody = EntityUtils.toString(entity);
                
                result.put("status", String.valueOf(response.getStatusLine().getStatusCode()));
                result.put("result", responseBody);
                result.put("header", Arrays.toString(response.getAllHeaders()));
                result.put("proxyHost", Config.TARGET_HOST + ":" + Config.TARGET_PORT);
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("Error forwarding request: " + e.getMessage());
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
     * 获取过滤配置
     */
    public Map<String, Object> getFilterConfig() throws IOException {
        Map<String, Object> config = new HashMap<>();
        
        // 构建请求URL
        String targetUrl = String.format("http://%s:%s/api/config/filter", 
                Config.TARGET_HOST, Config.TARGET_PORT);
        
        // 创建HTTP客户端并设置超时
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
                    config.put("includedomain", data.get("includedomain").getAsJsonArray());
                    config.put("excludedomain", data.get("excludedomain").getAsJsonArray());
                    config.put("filtersuffix", data.get("filtersuffix").getAsJsonArray());
                    config.put("addrport", data.get("addrport").getAsString());
                    config.put("sslinsecure", data.get("sslinsecure").getAsBoolean());
                }
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("Error getting filter config: " + e.getMessage());
        }
        
        return config;
    }
    
    /**
     * 获取扫描速率配置
     */
    public Map<String, Object> getScanRateConfig() throws IOException {
        Map<String, Object> config = new HashMap<>();
        
        // 构建请求URL
        String targetUrl = String.format("http://%s:%s/api/config/scanrate", 
                Config.TARGET_HOST, Config.TARGET_PORT);
        
        // 创建HTTP客户端并设置超时
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
                    config.put("globalrate", data.get("globalrate").getAsInt());
                    config.put("globalrateunit", data.get("globalrateunit").getAsString());
                    config.put("templateconcurrency", data.get("templateconcurrency").getAsInt());
                    config.put("hostconcurrency", data.get("hostconcurrency").getAsInt());
                    // 其他配置...
                }
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("Error getting scan rate config: " + e.getMessage());
        }
        
        return config;
    }
    
    /**
     * 获取扫描结果统计
     */
    public Map<String, Object> getScanStats() throws IOException {
        Map<String, Object> stats = new HashMap<>();
        
        // 构建请求URL
        String targetUrl = String.format("http://%s:%s/api/scan/stats", 
                Config.TARGET_HOST, Config.TARGET_PORT);
        
        // 创建HTTP客户端并设置超时
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
                    stats.put("total", data.get("total").getAsInt());
                    stats.put("stats", data.get("stats").getAsJsonObject());
                }
            }
        } catch (Exception e) {
            BurpExtender.stderr.println("Error getting scan stats: " + e.getMessage());
        }
        
        return stats;
    }
} 