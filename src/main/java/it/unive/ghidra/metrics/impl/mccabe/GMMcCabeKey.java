package it.unive.ghidra.metrics.impl.mccabe;

import it.unive.ghidra.metrics.base.GMAbstractMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;

public class GMMcCabeKey extends GMAbstractMetricKey {
	private static int sn = 0;

	public GMMcCabeKey(String name) {
		super(GMiMetricKey.Type.NUMERIC, name, sn++);
	}

}
