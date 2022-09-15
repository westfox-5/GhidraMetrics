package it.unive.ghidra.metrics.base;

import javax.swing.JComponent;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;

public class GMBaseProvider<T extends GMetric> {
	private final Class<T> metricClz;
	protected final GhidraMetricsPlugin plugin;
	
	protected T metric;
	protected GMBaseMetricWindowManager<T> wm;
	
	protected Function prevFn; // to detect if location has changed to new fn

	public GMBaseProvider(GhidraMetricsPlugin plugin, Class<T> metricClz) {
		this.plugin = plugin;
		this.metricClz = metricClz;
		
		init();
	}

	private final void init() {
		metric = GMetric.initialize(metricClz, getCurrentProgram());
		wm = GMetric.windowManagerFor(metric);
		
		wm.init();
	}

	public final T getMetric() {
		return metric;
	}

	public Class<T> getMetricClz() {
		return metricClz;
	}
	
	
	public final Program getCurrentProgram() {
		return plugin.getCurrentProgram();
	}

	public final JComponent getComponent() {
		return wm.getComponent();
	}

	public void locationChanged(ProgramLocation loc) {
		Function fn = getCurrentProgram().getFunctionManager().getFunctionContaining(loc.getAddress());
		
		if (fn == null)
			return;
		
		if (prevFn == null || (prevFn != null && !equals(prevFn, fn))) {
			prevFn = fn;
			
			metric.functionChanged(fn);
			wm.revalidate();
			wm.refresh();
		}
	}
	
	
	private static boolean equals(Function f1, Function f2) {
		if (f1 != null && f2 != null)
			return f1.getEntryPoint().equals(f2.getEntryPoint());
		return false;
	}
	
	
}