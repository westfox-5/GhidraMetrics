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
		metricLookup.put(GMHalstead.NAME, GMHalstead.class);
		metricLookup.put(GMNCD.NAME, GMNCD.class);
		metricLookup.put(GMMcCabe.NAME, GMMcCabe.class);

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

		if (GMHalstead.class.isAssignableFrom(metricClass)) {
			return new GMHalsteadProvider(plugin);
		}

		if (GMNCD.class.isAssignableFrom(metricClass)) {
			return new GMNCDProvider(plugin);
		}

		if (GMMcCabe.class.isAssignableFrom(metricClass)) {
			return new GMMcCabeProvider(plugin);
		}

		throw new RuntimeException("ERROR: no mapping defined for metric '" + metricClass.getCanonicalName() + "'.");
	}

	public static GMiMetricProvider createHeadless(String metricName, Program program) {

		if (GMHalstead.NAME.equals(metricName)) {
			return new GMHalsteadProvider(program);
		}

		if (GMNCD.NAME.equals(metricName)) {
			return new GMNCDProvider(program);
		}

		if (GMMcCabe.NAME.equals(metricName)) {
			return new GMMcCabeProvider(program);
		}

		throw new RuntimeException("ERROR: no mapping defined for metric '" + metricName + "'.");
	}
}