package it.unive.ghidra.metrics.impl.halstead;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMAbstractMetricProvider;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead.GMHalsteadFunction;

public class GMHalsteadProvider extends GMAbstractMetricProvider<GMHalstead, GMHalsteadProvider, GMHalsteadWinManager> {

	private GMHalstead metricFn;
	
	public GMHalsteadProvider(Program program) {
		super(program, GMHalstead.class);
	}

	public GMHalsteadProvider(GhidraMetricsPlugin plugin) {
		super(plugin, GMHalstead.class, GMHalsteadWinManager.class);
	}

	@Override
	public Collection<GMHalstead> getMetricsForExport() {
		List<GMHalstead> list = new ArrayList<>(super.getMetricsForExport());

		if (getMetricFn() != null) {

			// in headless mode, always add halsteadFunction
			// since halsteadFunction != null IFF user has provided FUNCTION parameter for
			// analysis
			if (isHeadlessMode()) {
				list.add(getMetricFn());
			}

			// in non headless mode, add halsteadFunction IFF
			// halsteadFunction != null AND windowManager is currently showing function
			// analysis (function tab)
			else {
				if (getWinManager().isFunctionTabVisible()) {
					list.add(getMetricFn());
				}
			}
		}

		return list;
	}

	@Override
	public void functionChanged(Function fn) {
		this.metricFn = new GMHalsteadFunction(this, fn);
		metricFn.init();
		
		getWinManager().revalidate();
	}

	public GMHalstead getMetricFn() {
		return metricFn;
	}
}
