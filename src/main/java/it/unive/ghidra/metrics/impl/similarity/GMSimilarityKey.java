package it.unive.ghidra.metrics.impl.similarity;

import java.nio.file.Path;

import it.unive.ghidra.metrics.base.GMBaseMeasureKey;
import it.unive.ghidra.metrics.base.interfaces.GMMeasureKey;

public class GMSimilarityKey extends GMBaseMeasureKey {
	private static int sn = 0;
	
	private final Path path;

	public GMSimilarityKey(Path path) {
		super(GMMeasureKey.Type.NUMERIC, path.getFileName().toString(), sn++);
		this.path = path;
	}

	public Path getPath() {
		return path;
	}
}
