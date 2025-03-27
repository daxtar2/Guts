package burp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 工具类
 */
public class Utils {
    /**
     * 获取插件欢迎信息
     */
    public static String getBanner() {
        return "Guts Burp Extension v1.0 Loaded!\n" +
               "Author: daxtar2\n" +
               "------------------------------------------------\n" +
               "将流量转发到Guts漏洞扫描系统";
    }

    /**
     * 更新请求计数器
     */
    public static void updateRequestCount() {
        Config.REQUEST_COUNT++;
        if (GUI.lbRequestCount != null) {
            GUI.lbRequestCount.setText(String.valueOf(Config.REQUEST_COUNT));
        }
    }

    /**
     * 更新成功计数器
     */
    public static void updateSuccessCount() {
        Config.SUCCESS_COUNT++;
        if (GUI.lbSuccesCount != null) {
            GUI.lbSuccesCount.setText(String.valueOf(Config.SUCCESS_COUNT));
        }
    }

    /**
     * 更新失败计数器
     */
    public static void updateFailCount() {
        Config.FAIL_COUNT++;
        if (GUI.lbFailCount != null) {
            GUI.lbFailCount.setText(String.valueOf(Config.FAIL_COUNT));
        }
    }

    /**
     * 判断字符串是否匹配正则表达式
     */
    public static boolean isMathch(String regex, String str) {
        if (regex == null || regex.equals("") || str == null || str.equals("")) {
            return false;
        }
        String[] regs = regex.split("\\n");
        for (String reg : regs) {
            if (!reg.trim().equals("")) {
                Pattern pat = Pattern.compile(reg.trim());
                Matcher mat = pat.matcher(str);
                if (mat.find()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 将Unix换行符转换为标准换行符
     */
    public static String standardizeLineBreaks(String str) {
        return str.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n");
    }
} 