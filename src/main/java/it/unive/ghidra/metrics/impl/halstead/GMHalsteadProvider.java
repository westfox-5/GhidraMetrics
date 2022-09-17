package it.unive.ghidra.metrics.impl.halstead;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetricProvider;

public class GMHalsteadProvider extends GMBaseMetricProvider<GMHalstead, GMHalsteadProvider, GMHalsteadWinManager> {

	public GMHalsteadProvider(Program program) {
		super(program, GMHalstead.class);
	}

	public GMHalsteadProvider(GhidraMetricsPlugin plugin) {
		super(plugin, GMHalstead.class, GMHalsteadWinManager.class);
	}

	@Override
	public Collection<GMHalstead> getMetricsToExport() {
		List<GMHalstead> list = new ArrayList<>(super.getMetricsToExport());
		
		GMHalstead halsteadFn = getMetric().getHalsteadFunction();
		if (halsteadFn != null) {
			
			// in headless mode, always add halsteadFunction
			// since halsteadFunction != null IFF user has provided FUNCTION parameter for analysis
			if (isHeadlessMode()) {
				list.add(halsteadFn);
			}
			
			// in non headless mode, add halsteadFunction IFF
			// halsteadFunction != null AND windowManager is currently showing function analysis (function tab)
			else {
				if (getWinManager().isFunctionTabVisible()) {
					list.add(halsteadFn);
				}
			}
		}
		
		return list;
	}
	
}
