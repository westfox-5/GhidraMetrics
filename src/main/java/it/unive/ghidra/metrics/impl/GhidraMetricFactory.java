package it.unive.ghidra.metrics.impl;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter.FileFormat;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManager;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerGUI;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerHeadless;
import it.unive.ghidra.metrics.base.interfaces.GMZipper;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;
import it.unive.ghidra.metrics.impl.halstead.GMHalsteadManager;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabe;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabeManager;
import it.unive.ghidra.metrics.impl.similarity.GMSimilarity;
import it.unive.ghidra.metrics.impl.similarity.GMSimilarityManager;
import it.unive.ghidra.metrics.util.ZipHelper;

public class GhidraMetricFactory {

	private static final Map<String, Class<? extends GMMetricManager>> MANAGERS_TABLE = new HashMap<>();;
	private static final Map<String, String> METRICNAMES_TABLE = new HashMap<>();
	private static final Map<String, GMMetricExporter.FileFormat> FILEFORMATS_TABLE = new HashMap<>();
	private static final Map<String, GMZipper> ZIPPERS_TABLE = new HashMap<>();

	static { 
		MANAGERS_TABLE.put(GMHalstead.LOOKUP_NAME, 		GMHalsteadManager.class);
		MANAGERS_TABLE.put(GMSimilarity.LOOKUP_NAME, 	GMSimilarityManager.class);
		MANAGERS_TABLE.put(GMMcCabe.LOOKUP_NAME, 		GMMcCabeManager.class);

		METRICNAMES_TABLE.put(GMHalstead.NAME, 		GMHalstead.LOOKUP_NAME); 
		METRICNAMES_TABLE.put(GMSimilarity.NAME, 	GMSimilarity.LOOKUP_NAME);
		METRICNAMES_TABLE.put(GMMcCabe.NAME, 		GMMcCabe.LOOKUP_NAME);

		ZIPPERS_TABLE.put("zip", ZipHelper::zip);
		ZIPPERS_TABLE.put("gzip", ZipHelper::gzip);
		ZIPPERS_TABLE.put("rzip", ZipHelper::rzip);
		
		for (GMMetricExporter.FileFormat ff: FileFormat.values()) {
			FILEFORMATS_TABLE.put(ff.getExtension(), ff);
		}		
	}
	
	public static Collection<String> allMetrics() {
		return METRICNAMES_TABLE.keySet();
	}
	
	public static Collection<String> allFileFormats() {
		return FILEFORMATS_TABLE.keySet();
	}
	
	public static GMMetricExporter.FileFormat getFileFormat(String ext) {
		return FILEFORMATS_TABLE.get(ext);
	}
	
	public static Collection<String> allZippers() {
		return ZIPPERS_TABLE.keySet();
	}
	
	public static GMZipper getZipper(String name) {
		return ZIPPERS_TABLE.get(name);
	}
	

	public static GMMetricManagerGUI create(String metricName, GhidraMetricsPlugin plugin) {
		GMMetricManagerGUI manager = null;
		
		Class<? extends GMMetricManager> managerClz = lookupManagerByMetric(metricName);
		try {
			Constructor<? extends GMMetricManager> constructor = managerClz.getConstructor(GhidraMetricsPlugin.class);
			if ( constructor != null ) {
				manager = (GMMetricManagerGUI) constructor.newInstance(plugin);
				
				if ( !manager.isInitialized() ) {
					throw new InstantiationException("Manager not initialized");
				}
				
			}
		} catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			manager = null;
			e.printStackTrace();
			Msg.showError(plugin, plugin.getProvider().getComponent(), "Generic Error", "Could not instantiate metric '"+ metricName +"': "+ e.getMessage());
		}
		
		return manager;
	}

	public static GMMetricManagerHeadless createHeadless(String metricName, Program program) {
		GMMetricManagerHeadless manager = null;
		
		Class<? extends GMMetricManager> managerClz = lookupManagerByMetric(metricName);
		try {
			Constructor<? extends GMMetricManager> constructor = managerClz.getConstructor(Program.class);
			if ( constructor != null ) {
				manager = (GMMetricManagerHeadless) constructor.newInstance(program);

				if ( !manager.isInitialized() ) {
					throw new InstantiationException("Manager not initialized");
				}
			}
		} catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			manager = null;
			e.printStackTrace();
		}
		
		return manager;
	}

	private static Class<? extends GMMetricManager> lookupManagerByMetric(String metric) {
		
		if ( MANAGERS_TABLE.containsKey(metric) ) 
			return MANAGERS_TABLE.get(metric);
		
		if ( METRICNAMES_TABLE.containsKey(metric) ) 
			return lookupManagerByMetric( METRICNAMES_TABLE.get(metric) );
		
		throw new RuntimeException("No metrics for name: '"+ metric +"'");
	}
}