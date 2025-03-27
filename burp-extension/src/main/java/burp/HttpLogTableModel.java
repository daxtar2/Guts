package burp;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * HTTP日志表格模型
 */
public class HttpLogTableModel extends AbstractTableModel {
    private final List<LogEntry> log;
    private final String[] columnNames = {"#", "状态", "URL", "方法", "目标"};

    /**
     * 构造函数
     */
    public HttpLogTableModel() {
        log = new ArrayList<>();
    }

    /**
     * 获取行数
     */
    @Override
    public int getRowCount() {
        return log.size();
    }

    /**
     * 获取列数
     */
    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    /**
     * 获取列名
     */
    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    /**
     * 获取单元格值
     */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry entry = log.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return entry.getId();
            case 1:
                return entry.getResult().get("status");
            case 2:
                return entry.getUrl().toString();
            case 3:
                return entry.getMethod();
            case 4:
                return entry.getUrl().getHost();
            default:
                return null;
        }
    }

    /**
     * 获取列类型
     */
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return String.class;
        }
        return String.class;
    }

    /**
     * 添加日志条目
     */
    public void addLogEntry(LogEntry entry) {
        log.add(entry);
        fireTableRowsInserted(log.size() - 1, log.size() - 1);
    }

    /**
     * 清除日志
     */
    public void clearLogs() {
        log.clear();
        fireTableDataChanged();
    }

    /**
     * 获取日志条目
     */
    public LogEntry getLogEntry(int rowIndex) {
        return log.get(rowIndex);
    }
} 