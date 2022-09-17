package it.unive.ghidra.metrics.base.interfaces;

import java.math.BigDecimal;

public interface GMiMetricNumericValue extends GMiMetricValue<BigDecimal>{

	@Override
	BigDecimal getValue();
}
