package it.unive.ghidra.metrics.impl.halstead;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetricManager;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;

public class GMHalsteadManager extends GMBaseMetricManager<GMHalstead, GMHalsteadManager, GMHalsteadWinManager> {

	private GMHalstead metricFn;
	
	public GMHalsteadManager(Program program) {
		super(program, GMHalstead.class);
	}

	public GMHalsteadManager(GhidraMetricsPlugin plugin) {
		super(plugin, GMHalstead.class, GMHalsteadWinManager.class);
	}

	@Override
	public Collection<GMMetric> getExportableMetrics() {
		List<GMMetric> exportableMetrics = new ArrayList<>(super.getExportableMetrics());

		if (getMetricFn() != null) {
			// in headless mode, always add halsteadFunction
			// since halsteadFunction != null IFF user has provided FUNCTION parameter for
			// analysis
			if ( !guiEnabled ) {
				exportableMetrics.add(getMetricFn());
			}

			// in non headless mode, add halsteadFunction IFF
			// halsteadFunction != null AND windowManager is currently showing function
			// analysis (function tab)
			else {
				if (getWinManager().isFunctionTabVisible()) {
					exportableMetrics.add(getMetricFn());
				}
			}
		}

		return exportableMetrics;
	}

	public GMHalstead getMetricFn() {
		return metricFn;
	}
	
	protected void setMetricFn(GMHalstead metricFn) {
		this.metricFn = metricFn;
	}
}
