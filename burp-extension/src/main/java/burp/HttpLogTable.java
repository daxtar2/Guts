package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * HTTP日志表组件
 */
public class HttpLogTable extends JTable {
    private final HttpLogTableModel httpLogTableModel;

    public HttpLogTable(HttpLogTableModel httpLogTableModel) {
        super(httpLogTableModel);
        this.httpLogTableModel = httpLogTableModel;
        
        // 设置表格属性
        setAutoCreateRowSorter(true);
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component comp = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                // 设置对齐方式
                if (column == 0) {
                    setHorizontalAlignment(SwingConstants.CENTER);
                } else {
                    setHorizontalAlignment(SwingConstants.LEFT);
                }
                
                return comp;
            }
        });
        
        // 添加鼠标点击事件
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 1) {
                    Point p = e.getPoint();
                    int rowIndex = convertRowIndexToModel(rowAtPoint(p));
                    
                    if (rowIndex < 0 || httpLogTableModel.getRowCount() <= rowIndex) {
                        return;
                    }
                    
                    LogEntry logEntry = httpLogTableModel.getLogEntry(rowIndex);
                    GUI.requestViewer.setMessage(logEntry.getRequestResponse().getRequest(), true);
                    GUI.responseViewer.setMessage(logEntry.getRequestResponse().getResponse(), false);
                    
                    // 显示目标服务器响应结果
                    String result = logEntry.getResult().get("result");
                    if (result != null) {
                        GUI.proxyRspViewer.setMessage(result.getBytes(), false);
                    }
                }
            }
        });
    }

    public HttpLogTableModel getHttpLogTableModel() {
        return httpLogTableModel;
    }
} 