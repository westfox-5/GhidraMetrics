package it.unive.ghidra.metrics.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;

import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.GhidraMetricsProvider;
import it.unive.ghidra.metrics.base.GMBaseMetric;

public class GMButton<M extends GMBaseMetric<?>> extends JButton implements ActionListener {
	private static final long serialVersionUID = 1L;

	public static final <M extends GMBaseMetric<?>> GMButton<M> of(GhidraMetricsPlugin plugin, Class<M> metricClz) {
		return new GMButton<M>(plugin, metricClz);
	}

	private final String title;

	private final GhidraMetricsPlugin plugin;
	private final Class<M> metricClz;

	private GMButton(GhidraMetricsPlugin plugin, Class<M> metricClz) {
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
			GhidraMetricsProvider provider = plugin.getProvider();

			provider.showMetric(metricClz);
		}
	}

}
