package it.unive.ghidra.metrics.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;

import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.GhidraMetricsProvider;
import it.unive.ghidra.metrics.base.GMBaseMetricProvider;
import it.unive.ghidra.metrics.base.GMBaseMetric;
import it.unive.ghidra.metrics.base.GMBaseMetricWinManager;

public class GMMetricButton
	<M extends GMBaseMetric<M, P, W>,
	P extends GMBaseMetricProvider<M, P, W>,
	W extends GMBaseMetricWinManager<M, P, W>>
	extends JButton implements ActionListener {
	
	private static final long serialVersionUID = 1L;
	
	private final String title;

	private final GhidraMetricsPlugin plugin;
	private final Class<M> metricClz;

	public GMMetricButton(GhidraMetricsPlugin plugin, Class<M> metricClz) {
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
