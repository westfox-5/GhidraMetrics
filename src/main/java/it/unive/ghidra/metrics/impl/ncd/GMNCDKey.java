package it.unive.ghidra.metrics.impl.ncd;

import it.unive.ghidra.metrics.base.GMMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;

public class GMNCDKey extends GMMetricKey {
	
	public GMNCDKey(String name) {
		super(GMiMetricKey.Type.NUMERIC, name);
	}
}
