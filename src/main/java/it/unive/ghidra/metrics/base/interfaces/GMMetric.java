package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;
import java.util.function.Function;

public interface GMMetric {
	
	GMMetricController getController();
	
	String getName();

	Collection<GMMeasure<?>> getMeasures();

	GMMeasure<?> getMeasureValue(GMMeasureKey key);
	
	void clearMeasures();
	
	String[] getTableColumns();
	Function<GMMeasure<?>, Object[]> getTableRowFn();
}
