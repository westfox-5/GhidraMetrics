package it.unive.ghidra.metrics.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.border.EmptyBorder;

import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.GhidraMetricsProvider;
import it.unive.ghidra.metrics.base.GMMetricFactory;
import it.unive.ghidra.metrics.base.interfaces.GMiMetric;

public class GMMetricButton extends JButton implements ActionListener {
	private static final long serialVersionUID = 1L;
	
	private final GhidraMetricsPlugin plugin;
	private final Class<? extends GMiMetric<?,?,?>> metricClz;

	private final String metricName;
	
	public GMMetricButton(GhidraMetricsPlugin plugin, Class<? extends GMiMetric<?,?,?>> metricClz) {
		super();
		this.plugin = plugin;
		this.metricClz = metricClz;
		this.metricName = GMMetricFactory.metricNameByClass(metricClz);
		
		setText(metricName);
		setBorder(new EmptyBorder(10, 10, 10, 10));
		setActionCommand(metricClz.getSimpleName());
		addActionListener(this);
	}

	@Override
	public void actionPerformed(ActionEvent ae) {
		String actionCommand = ae.getActionCommand();
		if (actionCommand.equals(metricClz.getSimpleName())) {
			GhidraMetricsProvider provider = plugin.getProvider();

			provider.showMetric(metricClz);
		}
	}

}
