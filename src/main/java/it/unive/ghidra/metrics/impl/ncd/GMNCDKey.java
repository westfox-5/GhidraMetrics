package it.unive.ghidra.metrics.impl.ncd;

import it.unive.ghidra.metrics.base.GMBaseMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMMetricKey;

public class GMNCDKey extends GMBaseMetricKey {
	private static int sn = 0;

	public GMNCDKey(String name) {
		super(GMMetricKey.Type.NUMERIC, name, sn++);
	}
}
