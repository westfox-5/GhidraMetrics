package it.unive.ghidra.metrics.gui;

import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.border.EmptyBorder;

import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.GhidraMetricsProvider;

public class GMActionMetric extends JButton implements ActionListener {
	private static final long serialVersionUID = 1L;

	private final GhidraMetricsPlugin plugin;
	private final String metricName;

	public GMActionMetric(GhidraMetricsPlugin plugin, String metricName) {
		super();
		this.plugin = plugin;
		this.metricName = metricName;

		setText(metricName);
		setBorder(new EmptyBorder(10, 10, 10, 10));
		setActionCommand(metricName);
		setFont(new Font("Dialog", Font.BOLD | Font.ITALIC, 14));
		addActionListener(this);
	}

	@Override
	public void actionPerformed(ActionEvent ae) {
		String actionCommand = ae.getActionCommand();
		if (actionCommand.equals(metricName)) {
			GhidraMetricsProvider provider = plugin.getProvider();

			provider.showMetricWindow(metricName);
		}
	}

}
