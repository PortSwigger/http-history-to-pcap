import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;

public class BurpHistory2Pcap implements BurpExtension, ContextMenuItemsProvider {

    private Frame burpFrame;

    @Override
    public void initialize(MontoyaApi api) {
        burpFrame = api.userInterface().swingUtils().suiteFrame();
        api.extension().setName("BurpHistory2Pcap");
        api.userInterface().registerContextMenuItemsProvider(this);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();

        if (selected == null || selected.isEmpty() || event.toolType() != ToolType.PROXY) {
            return List.of();
        }

        JMenuItem exportItem = new JMenuItem("Export selected HTTP message(s) as PCAP");
        exportItem.addActionListener(e -> handleExport(selected));

        List<Component> menu = new ArrayList<>();
        menu.add(exportItem);
        return menu;
    }

    private WriteOptions renderOptions() {
        JPanel panel = new JPanel(new BorderLayout());

        JLabel fileLabel = new JLabel("Filepath: ");
        JTextField fileField = new JTextField(20);
        JButton browse = new JButton("Browse...");
        browse.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            if (fc.showSaveDialog(panel) == JFileChooser.APPROVE_OPTION) {
                fileField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });

        JPanel filePanel = new JPanel();
        filePanel.setLayout(new BoxLayout(filePanel, BoxLayout.X_AXIS));
        filePanel.add(fileLabel);
        filePanel.add(fileField);
        filePanel.add(browse);

        JCheckBox usePort80 = new JCheckBox("Use port 80 on all packets for better HTTP decode (instead of actual packet port)");
        usePort80.setSelected(true);
        JCheckBox useRealIPs = new JCheckBox("Use real server IP addresses");
        useRealIPs.setSelected(true);

        JPanel checkboxPanel = new JPanel();
        checkboxPanel.setLayout(new BoxLayout(checkboxPanel, BoxLayout.Y_AXIS));
        checkboxPanel.add(usePort80);
        checkboxPanel.add(useRealIPs);

        panel.add(filePanel, BorderLayout.CENTER);
        panel.add(checkboxPanel, BorderLayout.SOUTH);

        int result = JOptionPane.showConfirmDialog(
                burpFrame,
                panel,
                "Save PCAP",
                JOptionPane.OK_CANCEL_OPTION
        );
        if (result != JOptionPane.OK_OPTION) {
            return null;
        }

        return new WriteOptions(fileField.getText(), usePort80.isSelected(), useRealIPs.isSelected());
    }

    private void handleExport(List<HttpRequestResponse> selected) {
        WriteOptions writeOptions = renderOptions();
        if (writeOptions == null) {
            return;
        }

        Thread t = new Thread(() -> {
            String filename = writeOptions.filepath();
            if (!filename.endsWith(".pcap")) filename += ".pcap";
            try (BurpPcapWriter writer = new BurpPcapWriter(
                    filename, writeOptions.forcePort80(), writeOptions.resolveHostnames())) {
                writer.writeEntries(selected);
                JOptionPane.showMessageDialog(
                        burpFrame,
                        "PCAP saved: " + filename,
                        "Export complete",
                        JOptionPane.INFORMATION_MESSAGE
                );
            }
            catch (UnsatisfiedLinkError | Exception ex) {
                JOptionPane.showMessageDialog(
                        burpFrame,
                        "Export failed: " + ex,
                        "Error",
                        JOptionPane.ERROR_MESSAGE
                );
            }
        });
        t.start();
    }

    private record WriteOptions(String filepath, boolean forcePort80, boolean resolveHostnames) {}
}
