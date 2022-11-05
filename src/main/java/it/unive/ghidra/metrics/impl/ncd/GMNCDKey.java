package it.unive.ghidra.metrics.impl.ncd;

import it.unive.ghidra.metrics.base.GMAbstractMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;

public class GMNCDKey extends GMAbstractMetricKey {
	private static int sn = 0;
	
	public GMNCDKey(String name) {
		super(GMiMetricKey.Type.NUMERIC, name, sn++);
	}
}
