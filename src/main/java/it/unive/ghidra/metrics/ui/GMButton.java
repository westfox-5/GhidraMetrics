package it.unive.ghidra.metrics.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;

import it.unive.ghidra.metrics.GMProvider;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMetric;

public class GMButton<T extends GMetric> extends JButton implements ActionListener {
	private static final long serialVersionUID = 1L;

	public static final <T extends GMetric> GMButton<T> of(
			GhidraMetricsPlugin plugin, Class<T> metricClz) {
		return new GMButton<T>(plugin, metricClz);
	}

	private final String title;

	private final GhidraMetricsPlugin plugin;
	private final Class<T> metricClz;

	private GMButton(GhidraMetricsPlugin plugin, Class<T> metricClz) {
		super();
		this.plugin = plugin;
		this.metricClz = metricClz;
		this.title = metricClz.getSimpleName();

		setText(title);
		setActionCommand(title);
		addActionListener(this);
	}

	@Override
	public void actionPerformed(ActionEvent ae) {
		String actionCommand = ae.getActionCommand();
		if (actionCommand.equals(title)) {
			GMProvider provider = plugin.getProvider();

			provider.showMetric(metricClz);
		}
	}

}
