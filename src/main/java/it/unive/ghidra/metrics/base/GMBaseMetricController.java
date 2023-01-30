package it.unive.ghidra.metrics.base;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMetricControllerGUI;
import it.unive.ghidra.metrics.base.interfaces.GMMetricControllerHeadless;

//@formatter:off
public abstract class GMBaseMetricController<
	M extends GMBaseMetric<M, C, W>, 
	C extends GMBaseMetricController<M, C, W>, 
	W extends GMBaseMetricWindow<M, C, W>>
implements GMMetricControllerGUI, GMMetricControllerHeadless {
//@formatter:on
	protected final boolean guiEnabled;
	protected final GhidraMetricsPlugin plugin;
	protected final Program program;

	private final boolean initialized;

	protected M metric;
	protected W window;

	private Function prevFn;
	private M metricFn;
	
	protected abstract void init();

	public GMBaseMetricController(Program program, Class<M> metricClass) {
		this.plugin = null;
		this.program = program;
		this.guiEnabled = false;

		this.initialized = _init(metricClass, null);
	}

	public GMBaseMetricController(GhidraMetricsPlugin plugin, Class<M> metricClass, Class<W> windowClass) {
		this.plugin = plugin;
		this.program = plugin.getCurrentProgram();
		this.guiEnabled = true;

		this.initialized = _init(metricClass, windowClass);
	}
	

	private final boolean _init(Class<M> metricClass, Class<W> windowClass) {
		
		if ( !_initMetric(metricClass) )
			return false;

		if ( guiEnabled && !_initWindown(windowClass) )
			return false;
		
		init();

		return true;
	}
	
	
	@Override
	public void printException(Exception e) {
		e.printStackTrace();
		Msg.error(this, e);
		
		if ( guiEnabled ) {
			Msg.showError(this, getWindow().getComponent(), "Generic Error", e.getMessage());
		}
	}
	
	@Override
	public boolean isInitialized() {
		return initialized;
	}

	@Override
	public M getMetric() {
		return metric;
	}

	@Override
	public W getWindow() {
		return window;
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public GhidraMetricsPlugin getPlugin() {
		return plugin;
	}

	@Override
	public void locationChanged(ProgramLocation loc) {
		Function fn = getProgram().getFunctionManager().getFunctionContaining(loc.getAddress());

		if (fn == null) {
			if (metricFn != null) {
				metricFn = null;
				window.refresh();
			}
			return;
		}

		if (prevFn == null || (prevFn != null && !equals(prevFn, fn))) {
			prevFn = fn;
			
			functionChanged(fn);	
		}
	}
	
	@Override
	public void functionChanged(Function fn) {
		metric.functionChanged(fn);
		
		if ( guiEnabled ) {
			window.refresh();
		}
	}


	@Override
	public Collection<GMMetric> getExportableMetrics() {
		List<GMMetric> toExport = new ArrayList<>();

		toExport.add(getMetric());
		
		if (getMetricFn() != null) {
			toExport.add(getMetricFn());
		}

		return toExport;
	}

	public M getMetricFn() {
		return metricFn;
	}

	public void setMetricFn(M metricFn) {
		this.metricFn = metricFn;
	}

	private final boolean _initMetric(Class<M> metricClass) {
		try {
			Constructor<M> declaredConstructor = metricClass.getDeclaredConstructor(getClass());
			this.metric = declaredConstructor.newInstance(this);

		} catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
			printException(e);
			return false;
		}

		return metric._init();
	}

	private final boolean _initWindown(Class<W> windowClass) {
		try {
			Constructor<W> declaredConstructor = windowClass.getDeclaredConstructor(getClass());
			this.window = declaredConstructor.newInstance(this);

		} catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
			printException(e);
			return false;
		}

		return window.init();
	}


	private static boolean equals(Function f1, Function f2) {
		if (f1 != null && f2 != null)
			return f1.getEntryPoint().equals(f2.getEntryPoint());
		return false;
	}

}
