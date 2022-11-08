package it.unive.ghidra.metrics;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.base.interfaces.GMiMetric;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricProvider;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;
import it.unive.ghidra.metrics.impl.halstead.GMHalsteadProvider;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabe;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabeProvider;
import it.unive.ghidra.metrics.impl.ncd.GMNCD;
import it.unive.ghidra.metrics.impl.ncd.GMNCDProvider;

public class GhidraMetricsFactory {

	private static final Map<String, Class<? extends GMiMetric>> metricLookup;
	private static final Map<Class<? extends GMiMetric>, String> inverseMetricLookup;

	static {
		metricLookup = new HashMap<>();
		metricLookup.put(GMHalstead.NAME, GMHalstead.class); // Halstead
		metricLookup.put(GMNCD.NAME, GMNCD.class); // NCD Similarity
		metricLookup.put(GMMcCabe.NAME, GMMcCabe.class); // McCabe

		inverseMetricLookup = metricLookup.entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));
	}

	public static Class<? extends GMiMetric> metricClassByName(String name) {
		return metricLookup.get(name);
	}

	public static String metricNameByClass(Class<? extends GMiMetric> metricClz) {
		return inverseMetricLookup.get(metricClz);
	}

	public static Collection<Class<? extends GMiMetric>> allMetrics() {
		return metricLookup.values();
	}

	public static GMiMetricProvider create(GhidraMetricsPlugin plugin, Class<? extends GMiMetric> metricClass) {
		GMiMetricProvider provider = null;

		if (GMHalstead.class.isAssignableFrom(metricClass)) {
			provider = new GMHalsteadProvider(plugin);
		} else if (GMNCD.class.isAssignableFrom(metricClass)) {
			provider = new GMNCDProvider(plugin);
		} else if (GMMcCabe.class.isAssignableFrom(metricClass)) {
			provider = new GMMcCabeProvider(plugin);
		}

		if (provider == null)
			throw new RuntimeException("ERROR: no mapping defined for metric '" + metricClass.getCanonicalName() + "'.");

		if (!provider.isInitialized())
			return null;

		return provider;
	}

	public static GMiMetricProvider createHeadless(String metricName, Program program) {
		GMiMetricProvider provider = null;
		
		if (metricName == null)
			throw new RuntimeException("ERROR: metric name is required.");


		if (GMHalstead.NAME.toLowerCase().equals(metricName.toLowerCase())) {
			provider = new GMHalsteadProvider(program);
		} else if (GMNCD.NAME.equals(metricName)) {
			provider = new GMNCDProvider(program);
		} else if (GMMcCabe.NAME.equals(metricName)) {
			provider = new GMMcCabeProvider(program);
		}

		if (provider == null)
			throw new RuntimeException("ERROR: no mapping defined for metric '" + metricName + "'.");

		if (!provider.isInitialized())
			return null;

		return provider;
	}
}