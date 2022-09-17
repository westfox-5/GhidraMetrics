package it.unive.ghidra.metrics.base;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.GhidraMetricsProvider;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricProvider;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.export.GMExporter.Type;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;
import it.unive.ghidra.metrics.impl.halstead.GMHalsteadProvider;
import it.unive.ghidra.metrics.impl.ncd.GMNCD;
import it.unive.ghidra.metrics.impl.ncd.GMNCDProvider;

public class GMBaseMetricProvider<
	M extends GMBaseMetric<M, P, W>,
	P extends GMBaseMetricProvider<M, P, W>,
	W extends GMBaseMetricWinManager<M, P, W> 
> implements GMiMetricProvider<M, P, W> {
	
	@SuppressWarnings("unchecked")
	public static class GMMetricProviderFactory  {
		
		public static 
			<M extends GMBaseMetric<M, P, W>,
			P extends GMBaseMetricProvider<M, P, W>,
			W extends GMBaseMetricWinManager<M, P, W>> 
		P create(GhidraMetricsPlugin plugin, Class<M> metricClass) {
			
			if (GMHalstead.class.isAssignableFrom(metricClass)) {
				return (P) new GMHalsteadProvider(plugin);
			}
			
			if (GMNCD.class.isAssignableFrom(metricClass)) {
				return (P) new GMNCDProvider(plugin);
			}
			
			throw new RuntimeException("ERROR: no mapping defined for metric '"+ metricClass.getCanonicalName() +"'.");

		}
		
		public static 
			<M extends GMBaseMetric<M, P, W>,
			P extends GMBaseMetricProvider<M, P, W>,
			W extends GMBaseMetricWinManager<M, P, W>> 
		P createHeadless(String metricName, Program program) {
			
			if (GMHalstead.NAME.equals(metricName)) {
				return (P) new GMHalsteadProvider(program);
			}
			
			if (GMNCD.NAME.equals(metricName)) {
				return (P) new GMNCDProvider(program);
			}
			
			throw new RuntimeException("ERROR: no mapping defined for metric '"+ metricName +"'.");

		}
	}
	
	private final boolean headlessMode;
	protected final GhidraMetricsPlugin plugin;
	protected final Program program;
	
	protected M metric;
	protected W wm;
	
	private Function prevFn; // avoid recomputing metrics on same function!

	public GMBaseMetricProvider(Program program, Class<M> metricClass) {
		this.plugin = null;
		this.program = program;
		this.headlessMode = true;
		
		init(metricClass, null);
	}
	public GMBaseMetricProvider(GhidraMetricsPlugin plugin, Class<M> metricClass, Class<W> winManagerClass) {
		this.plugin = plugin;
		this.program = plugin.getCurrentProgram();
		this.headlessMode = false;
		
		init(metricClass, winManagerClass);
	}
	
	private final void init(Class<M> metricClass, Class<W> winManagerClass) {
		initMetric(metricClass);
		
		if (!isHeadlessMode()) {
			initWinManager(winManagerClass);
		}
	}

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
	public GhidraMetricsProvider getMainProvider() {
		return plugin.getProvider();
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

	public GMExporter.Builder makeExporter(Type exportType) {
		GMExporter.Builder builder = GMExporter.of(exportType, plugin); 
		getMetricsToExport().forEach(m -> builder.addMetric(m));
		
		if (!isHeadlessMode()) 
			builder.withFileChooser();
		
		
		return builder;
	}
	
	private final void initMetric(Class<M> metricClass) {
		try {
			Constructor<M> declaredConstructor = metricClass.getDeclaredConstructor(getClass());
			this.metric = declaredConstructor.newInstance(this);
			this.metric.init();

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
		
	}
	
	private final void initWinManager(Class<W> winManagerClass) {
		try {
			Constructor<W> declaredConstructor = winManagerClass.getDeclaredConstructor(getClass());
			this.wm = declaredConstructor.newInstance(this);
			this.wm.init();

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
		
	}
	
	
	
	private static boolean equals(Function f1, Function f2) {
		if (f1 != null && f2 != null)
			return f1.getEntryPoint().equals(f2.getEntryPoint());
		return false;
	}

}
