package it.unive.ghidra.metrics.impl.similarity;

import java.nio.file.Path;

import it.unive.ghidra.metrics.base.GMBaseMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMMetricKey;

public class GMSimilarityKey extends GMBaseMetricKey {
	private static int sn = 0;
	
	private final Path path;

	public GMSimilarityKey(Path path) {
		super(GMMetricKey.Type.NUMERIC, path.getFileName().toString(), sn++);
		this.path = path;
	}

	public Path getPath() {
		return path;
	}
}
