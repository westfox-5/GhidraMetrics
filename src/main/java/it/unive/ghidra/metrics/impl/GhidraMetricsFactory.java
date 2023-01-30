package it.unive.ghidra.metrics.impl;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter.FileFormat;
import it.unive.ghidra.metrics.base.interfaces.GMMetricController;
import it.unive.ghidra.metrics.base.interfaces.GMMetricControllerGUI;
import it.unive.ghidra.metrics.base.interfaces.GMMetricControllerHeadless;
import it.unive.ghidra.metrics.base.interfaces.GMZipper;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;
import it.unive.ghidra.metrics.impl.halstead.GMHalsteadController;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabe;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabeController;
import it.unive.ghidra.metrics.impl.similarity.GMSimilarity;
import it.unive.ghidra.metrics.impl.similarity.GMSimilarityController;
import it.unive.ghidra.metrics.util.ZipHelper;

public class GhidraMetricsFactory {

	private static final Map<String, Class<? extends GMMetricController>> CONTROLLERS_TABLE = new HashMap<>();;
	private static final Map<String, String> METRICNAMES_TABLE = new HashMap<>();
	private static final Map<String, GMMetricExporter.FileFormat> FILEFORMATS_TABLE = new HashMap<>();
	private static final Map<String, GMZipper> ZIPPERS_TABLE = new HashMap<>();

	static {
		CONTROLLERS_TABLE.put(GMHalstead.LOOKUP_NAME, GMHalsteadController.class);
		CONTROLLERS_TABLE.put(GMSimilarity.LOOKUP_NAME, GMSimilarityController.class);
		CONTROLLERS_TABLE.put(GMMcCabe.LOOKUP_NAME, GMMcCabeController.class);

		METRICNAMES_TABLE.put(GMHalstead.NAME, GMHalstead.LOOKUP_NAME);
		METRICNAMES_TABLE.put(GMMcCabe.NAME, GMMcCabe.LOOKUP_NAME);
		METRICNAMES_TABLE.put(GMSimilarity.NAME, GMSimilarity.LOOKUP_NAME);

		ZIPPERS_TABLE.put("zip", ZipHelper::zip);
		ZIPPERS_TABLE.put("gzip", ZipHelper::gzip);
		ZIPPERS_TABLE.put("rzip", ZipHelper::rzip);

		for (GMMetricExporter.FileFormat ff : FileFormat.values()) {
			FILEFORMATS_TABLE.put(ff.getExtension(), ff);
		}
	}

	public static Collection<String> allMetrics() {
		return allMetrics(true);
	}

	public static Collection<String> allMetrics(boolean sorted) {
		return sorted ? METRICNAMES_TABLE.keySet().stream().sorted().collect(Collectors.toUnmodifiableList())
				: METRICNAMES_TABLE.keySet();
	}

	public static Collection<String> allFileFormats() {
		return allFileFormats(true);
	}

	public static Collection<String> allFileFormats(boolean sorted) {
		return sorted ? FILEFORMATS_TABLE.keySet().stream().sorted().collect(Collectors.toUnmodifiableList())
				: FILEFORMATS_TABLE.keySet();
	}

	public static GMMetricExporter.FileFormat getFileFormat(String ext) {
		return FILEFORMATS_TABLE.get(ext);
	}

	public static Collection<String> allZippers() {
		return allZippers(true);
	}

	public static Collection<String> allZippers(boolean sorted) {
		return sorted ? ZIPPERS_TABLE.keySet().stream().sorted().collect(Collectors.toUnmodifiableList())
				: ZIPPERS_TABLE.keySet();
	}

	public static GMZipper getZipper(String name) {
		return ZIPPERS_TABLE.get(name);
	}

	public static GMMetricControllerGUI create(String metricName, GhidraMetricsPlugin plugin) {
		GMMetricControllerGUI manager = null;

		Class<? extends GMMetricController> managerClz = lookupControllerByMetric(metricName);
		try {
			Constructor<? extends GMMetricController> constructor = managerClz
					.getConstructor(GhidraMetricsPlugin.class);
			if (constructor != null) {
				manager = (GMMetricControllerGUI) constructor.newInstance(plugin);

				if (!manager.isInitialized()) {
					throw new InstantiationException("Manager not initialized");
				}

			}
		} catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException
				| IllegalArgumentException | InvocationTargetException e) {
			manager = null;
			e.printStackTrace();
			Msg.showError(plugin, plugin.getProvider().getComponent(), "Generic Error",
					"Could not instantiate metric '" + metricName + "': " + e.getMessage());
		}

		return manager;
	}

	public static GMMetricControllerHeadless createHeadless(String metricName, Program program) {
		GMMetricControllerHeadless manager = null;

		Class<? extends GMMetricController> managerClz = lookupControllerByMetric(metricName);
		try {
			Constructor<? extends GMMetricController> constructor = managerClz.getConstructor(Program.class);
			if (constructor != null) {
				manager = (GMMetricControllerHeadless) constructor.newInstance(program);

				if (!manager.isInitialized()) {
					throw new InstantiationException("Manager not initialized");
				}
			}
		} catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException
				| IllegalArgumentException | InvocationTargetException e) {
			manager = null;
			e.printStackTrace();
		}

		return manager;
	}

	private static Class<? extends GMMetricController> lookupControllerByMetric(String metric) {

		if (CONTROLLERS_TABLE.containsKey(metric))
			return CONTROLLERS_TABLE.get(metric);

		if (METRICNAMES_TABLE.containsKey(metric))
			return lookupControllerByMetric(METRICNAMES_TABLE.get(metric));

		throw new RuntimeException("No metrics for name: '" + metric + "'");
	}
}