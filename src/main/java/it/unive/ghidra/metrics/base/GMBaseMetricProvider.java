package it.unive.ghidra.metrics.base;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import javax.swing.JComponent;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.export.GMExporter.Type;

public class GMBaseMetricProvider<M extends GMBaseMetric<?>> {
	private final Class<M> metricClz;
	protected final GhidraMetricsPlugin plugin;
	
	protected M metric;
	protected GMBaseMetricWindowManager<M> wm;
	
	protected Function prevFn; // to detect if location has changed to new fn

	public GMBaseMetricProvider(GhidraMetricsPlugin plugin, Class<M> metricClz) {
		this.plugin = plugin;
		this.metricClz = metricClz;
		
		init();
	}

	private final void init() {
		metric = GMBaseMetric.initialize(metricClz, this);
		
		wm = GMBaseMetricProvider.initializeWindowManager(metric, this);
		wm.init();
	}

	public final M getMetric() {
		return metric;
	}

	public Class<M> getMetricClz() {
		return metricClz;
	}
	
	public GMBaseMetricWindowManager<M> getWindowManager() {
		return wm;
	}
	
	public final Program getCurrentProgram() {
		return plugin.getCurrentProgram();
	}

	public final JComponent getComponent() {
		return wm.getComponent();
	}
	
	
	public GMExporter createExporter(Type exportType) {
		GMExporter.Builder builder = GMExporter.of(exportType, plugin).withFileChooser();
		metric.getMetricsToExport().forEach(m -> builder.addMetric(m));
		return builder.build();
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
	

	@SuppressWarnings("unchecked")
	public static <M extends GMBaseMetric<?>> GMBaseMetricWindowManager<M> initializeWindowManager(M metric, GMBaseMetricProvider<M> provider) {
		try {
			Class<? extends GMBaseMetricWindowManager<M>> wmClz = (Class<? extends GMBaseMetricWindowManager<M>>) metric.getWindowManagerClass();
			
			Constructor<? extends GMBaseMetricWindowManager<M>> declaredConstructor = wmClz.getDeclaredConstructor(provider.getClass());
			GMBaseMetricWindowManager<M> newInstance = declaredConstructor.newInstance(provider);
		
			return newInstance;
		// TODO handle these exceptions more gracefully
		} catch (InstantiationException x) {
		    x.printStackTrace();
		} catch (IllegalAccessException x) {
		    x.printStackTrace();
		} catch (InvocationTargetException x) {
		    x.printStackTrace();
		} catch (NoSuchMethodException x) {
		    x.printStackTrace();
		}
				
		return null;
	}

}