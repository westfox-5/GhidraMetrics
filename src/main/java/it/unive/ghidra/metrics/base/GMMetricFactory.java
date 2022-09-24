package it.unive.ghidra.metrics.base;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.interfaces.GMiMetric;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricProvider;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricWinManager;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;
import it.unive.ghidra.metrics.impl.halstead.GMHalsteadProvider;
import it.unive.ghidra.metrics.impl.ncd.GMNCD;
import it.unive.ghidra.metrics.impl.ncd.GMNCDProvider;

@SuppressWarnings("unchecked")
public class GMMetricFactory {

	private static final Map<String, Class<? extends GMiMetric<?, ?, ?>>> metricLookup;
	private static final Map<Class<? extends GMiMetric<?, ?, ?>>, String> inverseMetricLookup;

	static {
		metricLookup = new HashMap<>();
		metricLookup.put(GMHalstead.NAME, GMHalstead.class);
		metricLookup.put(GMNCD.NAME, GMNCD.class);
		
		
		inverseMetricLookup = metricLookup.entrySet().stream()
	       .collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));
	}

	public static Class<? extends GMiMetric<?, ?, ?>> metricClassByName(String name) {
		return metricLookup.get(name);
	}
	
	public static String metricNameByClass(Class<? extends GMiMetric<?,?,?>> metricClz) {
		return inverseMetricLookup.get(metricClz);
	}

	public static Collection<Class<? extends GMiMetric<?, ?, ?>>> allMetrics() {
		return metricLookup.values();
	}

	public static <M extends GMiMetric<M, P, W>, P extends GMiMetricProvider<M, P, W>, W extends GMiMetricWinManager<M, P, W>> 
		P create(GhidraMetricsPlugin plugin, Class<M> metricClass) {

		if (GMHalstead.class.isAssignableFrom(metricClass)) {
			return (P) new GMHalsteadProvider(plugin);
		}

		if (GMNCD.class.isAssignableFrom(metricClass)) {
			return (P) new GMNCDProvider(plugin);
		}

		throw new RuntimeException("ERROR: no mapping defined for metric '" + metricClass.getCanonicalName() + "'.");

	}

	public static <M extends GMiMetric<M, P, W>, P extends GMiMetricProvider<M, P, W>, W extends GMiMetricWinManager<M, P, W>> 
		P createHeadless(String metricName, Program program) {

		if (GMHalstead.NAME.equals(metricName)) {
			return (P) new GMHalsteadProvider(program);
		}

		if (GMNCD.NAME.equals(metricName)) {
			return (P) new GMNCDProvider(program);
		}

		throw new RuntimeException("ERROR: no mapping defined for metric '" + metricName + "'.");

	}
}