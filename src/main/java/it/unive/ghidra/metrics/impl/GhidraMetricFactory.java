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
import it.unive.ghidra.metrics.base.interfaces.GMMetricManager;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerGUI;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerHeadless;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;
import it.unive.ghidra.metrics.impl.halstead.GMHalsteadManager;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabe;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabeManager;
import it.unive.ghidra.metrics.impl.similarity.GMSimilarity;
import it.unive.ghidra.metrics.impl.similarity.GMSimilarityManager;

public class GhidraMetricFactory {

	private static final Map<String, Class<? extends GMMetricManager>> MANAGERS_TABLE = new HashMap<>();;
	private static final Map<String, String> METRICNAMES_TABLE = new HashMap<>();

	static { 
		MANAGERS_TABLE.put(GMHalstead.LOOKUP_NAME, 		GMHalsteadManager.class);
		MANAGERS_TABLE.put(GMSimilarity.LOOKUP_NAME, 	GMSimilarityManager.class);
		MANAGERS_TABLE.put(GMMcCabe.LOOKUP_NAME, 		GMMcCabeManager.class);


		METRICNAMES_TABLE.put(GMHalstead.NAME, 		GMHalstead.LOOKUP_NAME); 
		METRICNAMES_TABLE.put(GMSimilarity.NAME, 	GMSimilarity.LOOKUP_NAME);
		METRICNAMES_TABLE.put(GMMcCabe.NAME, 		GMMcCabe.LOOKUP_NAME);		
	}
	
	private static final Map<Class<? extends GMMetricManager>, String> INVERSE_MANAGERS_TABLE;
	static {
		INVERSE_MANAGERS_TABLE = MANAGERS_TABLE.entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));		
	}
	
	public static Collection<Class<? extends GMMetricManager>> allMetricManagers() {
		return MANAGERS_TABLE.values();
	}
	
	public static String metricLookupNameByManager(Class<? extends GMMetricManager> managerClass) {
		return INVERSE_MANAGERS_TABLE.get(managerClass);
	}

	
	public static Collection<String> allMetricNames() {
		return METRICNAMES_TABLE.keySet();
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