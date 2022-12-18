package it.unive.ghidra.metrics;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerGUI;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerHeadless;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManager;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;
import it.unive.ghidra.metrics.impl.halstead.GMHalsteadManager;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabe;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabeManager;
import it.unive.ghidra.metrics.impl.ncd.GMNCD;
import it.unive.ghidra.metrics.impl.ncd.GMNCDManager;

public class GhidraMetricsFactory {

	private static final Map<String, Class<? extends GMMetricManager>> managersLookupTable;
	private static final Map<Class<? extends GMMetricManager>, String> inverseManagersLookupTable;
	private static final Map<String, String> metricNamesLookupTable;

	static {
		metricNamesLookupTable = new HashMap<>();
		metricNamesLookupTable.put(GMHalstead.NAME, GMHalstead.LOOKUP_NAME); 
		metricNamesLookupTable.put(GMNCD.NAME, GMNCD.LOOKUP_NAME);
		metricNamesLookupTable.put(GMMcCabe.NAME, GMMcCabe.LOOKUP_NAME);
		
		managersLookupTable = new HashMap<>();
		managersLookupTable.put(GMHalstead.LOOKUP_NAME, GMHalsteadManager.class);
		managersLookupTable.put(GMNCD.LOOKUP_NAME, GMNCDManager.class);
		managersLookupTable.put(GMMcCabe.LOOKUP_NAME, GMMcCabeManager.class);

		
		inverseManagersLookupTable = managersLookupTable.entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));
	}
	
	public static Collection<Class<? extends GMMetricManager>> allMetricManagers() {
		return managersLookupTable.values();
	}
	
	public static String metricLookupNameByManager(Class<? extends GMMetricManager> managerClass) {
		return inverseManagersLookupTable.get(managerClass);
	}

	
	public static Collection<String> allMetricNames() {
		return metricNamesLookupTable.keySet();
	}
	

	public static GMMetricManagerGUI create(String metricName, GhidraMetricsPlugin plugin) {
		GMMetricManagerGUI manager = null;
		
		Class<? extends GMMetricManager> managerClz = lookupManagerByMetricName(metricName);
		try {
			Constructor<? extends GMMetricManager> constructor = managerClz.getConstructor(GhidraMetricsPlugin.class);
			if ( constructor != null ) {
				manager = (GMMetricManagerGUI) constructor.newInstance(plugin);
			}
		} catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			e.printStackTrace();
			Msg.showError(plugin, plugin.getProvider().getComponent(), "Generic Error", "Could not instantiate metric '"+ metricName +"'");
		}
		
		if (!manager.isInitialized()) {
			return null;
		}
		
		return manager;
	}

	public static GMMetricManagerHeadless createHeadless(String metricName, Program program) {
		GMMetricManagerHeadless manager = null;
		
		Class<? extends GMMetricManager> managerClz = lookupManagerByMetricName(metricName);
		try {
			Constructor<? extends GMMetricManager> constructor = managerClz.getConstructor(Program.class);
			if ( constructor != null ) {
				manager = (GMMetricManagerHeadless) constructor.newInstance(program);
			}
		} catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			e.printStackTrace();
		}
		
		return manager;
	}

	private static Class<? extends GMMetricManager> lookupManagerByMetricName(String metricName) {
		
		if ( managersLookupTable.containsKey(metricName) ) 
			return managersLookupTable.get(metricName);
		
		if ( metricNamesLookupTable.containsKey(metricName) ) 
			return lookupManagerByMetricName( metricNamesLookupTable.get(metricName) );
		
		throw new RuntimeException("No metrics for name: '"+ metricName +"'");
	}
}