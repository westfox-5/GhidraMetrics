package it.unive.ghidra.metrics.impl.similarity;

import it.unive.ghidra.metrics.base.GMBaseMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMMetricKey;

public class GMSimilarityKey extends GMBaseMetricKey {
	private static int sn = 0;

	public GMSimilarityKey(String name) {
		super(GMMetricKey.Type.NUMERIC, name, sn++);
	}
}
