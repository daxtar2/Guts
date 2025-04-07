package burp;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * HTTP日志表格模型
 */
public class HttpLogTableModel extends AbstractTableModel {
    private static final long serialVersionUID = 1L;
    
    private final List<LogEntry> log = new ArrayList<>();
    
    private final String[] columnNames = {
        "#", "URL", "方法", "状态", "扫描结果", "严重程度", "时间戳"
    };
    
    /**
     * 获取列数
     */
    @Override
    public int getColumnCount() {
        return columnNames.length;
    }
    
    /**
     * 获取行数
     */
    @Override
    public int getRowCount() {
        return log.size();
    }
    
    /**
     * 获取列名
     */
    @Override
    public String getColumnName(int columnIndex) {
        return columnNames[columnIndex];
    }
    
    /**
     * 获取单元格值
     */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);
        
        switch (columnIndex) {
            case 0: // #
                return logEntry.getId();
            case 1: // URL
                return logEntry.getUrl().toString();
            case 2: // 方法
                return logEntry.getMethod();
            case 3: // 状态
                Map<String, String> result = logEntry.getResult();
                if (result != null && result.containsKey("status")) {
                    return result.get("status");
                }
                return "N/A";
            case 4: // 扫描结果
                result = logEntry.getResult();
                if (result != null && result.containsKey("scanStatus")) {
                    return result.get("scanStatus");
                }
                return "处理中";
            case 5: // 严重程度
                // 从结果中解析严重程度，如果有的话
                result = logEntry.getResult();
                if (result != null && result.containsKey("severity")) {
                    return result.get("severity");
                }
                return "-";
            case 6: // 时间戳
                return logEntry.getTimestamp();
            default:
                return "";
        }
    }
    
    /**
     * 获取单元格的类
     */
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0: // #
                return String.class;
            case 1: // URL
                return String.class;
            case 2: // 方法
                return String.class;
            case 3: // 状态
                return String.class;
            case 4: // 扫描结果
                return String.class;
            case 5: // 严重程度
                return String.class;
            case 6: // 时间戳
                return String.class;
            default:
                return Object.class;
        }
    }
    
    /**
     * 添加日志条目
     */
    public int addLogEntry(LogEntry logEntry) {
        log.add(logEntry);
        fireTableRowsInserted(log.size() - 1, log.size() - 1);
        return log.size() - 1;
    }
    
    /**
     * 更新日志条目
     */
    public void updateLogEntry(int index, Map<String, String> result) {
        if (index >= 0 && index < log.size()) {
            LogEntry entry = log.get(index);
            entry.setResult(result);
            fireTableRowsUpdated(index, index);
        }
    }
    
    /**
     * 获取日志条目
     */
    public LogEntry getLogEntry(int index) {
        if (index >= 0 && index < log.size()) {
            return log.get(index);
        }
        return null;
    }
    
    /**
     * 清空日志
     */
    public void clearLog() {
        int size = log.size();
        log.clear();
        fireTableRowsDeleted(0, size > 0 ? size - 1 : 0);
    }
    
    /**
     * 获取所有日志条目
     */
    public List<LogEntry> getAllLogEntries() {
        return new ArrayList<>(log);
    }
} 