package it.unive.ghidra.metrics.base;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.Collections;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricProvider;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.export.GMExporter.Type;

//@formatter:off
public abstract class GMAbstractMetricProvider<
	M extends GMAbstractMetric<M, P, W>, 
	P extends GMAbstractMetricProvider<M, P, W>, 
	W extends GMAbstractMetricWindowManager<M, P, W>>
implements GMiMetricProvider {
//@formatter:on
	private final boolean headlessMode;
	protected final GhidraMetricsPlugin plugin;
	protected final Program program;

	private final boolean initialized;

	protected M metric;
	protected W wm;

	private Function prevFn;

	public GMAbstractMetricProvider(Program program, Class<M> metricClass) {
		this.plugin = null;
		this.program = program;
		this.headlessMode = true;

		this.initialized = _init(metricClass, null);
	}

	public GMAbstractMetricProvider(GhidraMetricsPlugin plugin, Class<M> metricClass, Class<W> winManagerClass) {
		this.plugin = plugin;
		this.program = plugin.getCurrentProgram();
		this.headlessMode = false;

		this.initialized = _init(metricClass, winManagerClass);
	}

	@Override
	public boolean isInitialized() {
		return initialized;
	}

	@Override
	public boolean isHeadlessMode() {
		return headlessMode;
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

			metric.functionChanged(fn);
			wm.revalidate();
			wm.refresh();
		}
	}

	@Override
	public GMExporter.Builder makeExporter(Type exportType) {
		GMExporter.Builder builder = GMExporter.of(exportType, plugin).addMetrics(getMetricsForExport());

		if (!isHeadlessMode())
			builder.withFileChooser();

		return builder;
	}

	public Collection<? extends M> getMetricsForExport() {
		return Collections.singletonList(getMetric());
	}

	private final boolean _createMetric(Class<M> metricClass) {
		try {
			Constructor<M> declaredConstructor = metricClass.getDeclaredConstructor(getClass());
			this.metric = declaredConstructor.newInstance(this);

			// TODO handle these exceptions more gracefully
		} catch (InstantiationException x) {
			x.printStackTrace();
			return false;
		} catch (IllegalAccessException x) {
			x.printStackTrace();
			return false;
		} catch (InvocationTargetException x) {
			x.printStackTrace();
			return false;
		} catch (NoSuchMethodException x) {
			x.printStackTrace();
			return false;
		}

		return this.metric._init();
	}

	private final boolean _createWindownManager(Class<W> winManagerClass) {
		try {
			Constructor<W> declaredConstructor = winManagerClass.getDeclaredConstructor(getClass());
			this.wm = declaredConstructor.newInstance(this);

			// TODO handle these exceptions more gracefully
		} catch (InstantiationException x) {
			x.printStackTrace();
			return false;
		} catch (IllegalAccessException x) {
			x.printStackTrace();
			return false;
		} catch (InvocationTargetException x) {
			x.printStackTrace();
			return false;
		} catch (NoSuchMethodException x) {
			x.printStackTrace();
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

		if (initialized && !isHeadlessMode()) {
			_createWindownManager(winManagerClass);
		}

		return initialized;
	}

	private static boolean equals(Function f1, Function f2) {
		if (f1 != null && f2 != null)
			return f1.getEntryPoint().equals(f2.getEntryPoint());
		return false;
	}

}
