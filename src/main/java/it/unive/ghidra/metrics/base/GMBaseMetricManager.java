package it.unive.ghidra.metrics.base;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.Collections;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerGUI;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerHeadless;

//@formatter:off
public abstract class GMBaseMetricManager<
	M extends GMBaseMetric<M, P, W>, 
	P extends GMBaseMetricManager<M, P, W>, 
	W extends GMBaseMetricWindowManager<M, P, W>>
implements GMMetricManagerGUI, GMMetricManagerHeadless {
//@formatter:on
	protected final boolean guiEnabled;
	protected final GhidraMetricsPlugin plugin;
	protected final Program program;

	private final boolean initialized;

	protected M metric;
	protected W wm;

	private Function prevFn;
	
	protected abstract void init();

	public GMBaseMetricManager(Program program, Class<M> metricClass) {
		this.plugin = null;
		this.program = program;
		this.guiEnabled = false;

		this.initialized = _init(metricClass, null);
	}

	public GMBaseMetricManager(GhidraMetricsPlugin plugin, Class<M> metricClass, Class<W> winManagerClass) {
		this.plugin = plugin;
		this.program = plugin.getCurrentProgram();
		this.guiEnabled = true;

		this.initialized = _init(metricClass, winManagerClass);
	}
	
	@Override
	public void printException(Exception e) {
		e.printStackTrace();
		Msg.error(this, e);
		
		if ( guiEnabled ) {
			Msg.showError(this, getWinManager().getComponent(), "Generic Error", e.getMessage());
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
	public W getWinManager() {
		return wm;
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

		if (fn == null)
			return;

		if (prevFn == null || (prevFn != null && !equals(prevFn, fn))) {
			prevFn = fn;
			
			functionChanged(fn);	
		}
	}
	
	@Override
	public void functionChanged(Function fn) {
		metric.functionChanged(fn);
		
		if ( guiEnabled ) {
			wm.revalidate();
			wm.refresh();
		}
	}

	@Override
	public Collection<GMMetric> getExportableMetrics() {
		return Collections.singletonList(getMetric());
	}

	private final boolean _createMetric(Class<M> metricClass) {
		try {
			Constructor<M> declaredConstructor = metricClass.getDeclaredConstructor(getClass());
			this.metric = declaredConstructor.newInstance(this);

		} catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
			printException(e);
			return false;
		}

		return this.metric._init();
	}

	private final boolean _createWindownManager(Class<W> winManagerClass) {
		try {
			Constructor<W> declaredConstructor = winManagerClass.getDeclaredConstructor(getClass());
			this.wm = declaredConstructor.newInstance(this);

		} catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
			printException(e);
			return false;
		}

		Swing.runIfSwingOrRunLater(() -> wm.init());

		if (metric != null) {
			wm.onMetricInitialized();
		}

		return true;
	}

	private final boolean _init(Class<M> metricClass, Class<W> winManagerClass) {
		boolean initialized = _createMetric(metricClass);

		if (initialized && guiEnabled) {
			_createWindownManager(winManagerClass);
		}
		
		if (initialized) {
			init();
		}

		return initialized;
	}

	private static boolean equals(Function f1, Function f2) {
		if (f1 != null && f2 != null)
			return f1.getEntryPoint().equals(f2.getEntryPoint());
		return false;
	}

}
