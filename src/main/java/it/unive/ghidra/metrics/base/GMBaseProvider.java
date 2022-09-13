package it.unive.ghidra.metrics.base;

import javax.swing.JComponent;
import javax.swing.JPanel;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;

public class GMBaseProvider<T extends GMetric> {
	private final Class<T> metricClz;
	protected final GhidraMetricsPlugin plugin;
	protected T metric;
	protected JPanel panel;

	public GMBaseProvider(GhidraMetricsPlugin plugin, Class<T> metricClz) {
		this.plugin = plugin;
		this.metricClz = metricClz;
		
		init();
	}

	public final T getMetric() {
		return metric;
	}

	public Class<T> getMetricClz() {
		return metricClz;
	}
	
	private final void init() {
		if (metric == null) {
			metric = GMetric.initialize(metricClz, getCurrentProgram());
		}
	}

	public final Program getCurrentProgram() {
		return plugin.getCurrentProgram();
	}

	public final JComponent getComponent() {
		return panel;
	}
	
}