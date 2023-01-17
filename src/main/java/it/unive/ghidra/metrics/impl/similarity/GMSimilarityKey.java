package it.unive.ghidra.metrics.impl.similarity;

import java.nio.file.Path;

import it.unive.ghidra.metrics.base.GMBaseMeasureKey;
import it.unive.ghidra.metrics.base.interfaces.GMMeasureKey;

public class GMSimilarityKey extends GMBaseMeasureKey {
	public static final String INFOKEY_THIS_PROGRAM = "this_program";
	private static int sn = 0;
	
	private final Path path;

	public GMSimilarityKey(Path thisPath, Path otherPath) {
		super(GMMeasureKey.Type.NUMERIC, otherPath.getFileName().toString(), sn++);
		this.path = otherPath;
		
		addInfo(INFOKEY_THIS_PROGRAM, thisPath.getFileName().toString());
	}

	public Path getPath() {
		return path;
	}
}
