package it.unive.ghidra.metrics.impl.ncd;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import ghidra.program.model.listing.Function;
import it.unive.ghidra.metrics.base.GMBaseMetric;
import it.unive.ghidra.metrics.base.GMMetricValue;
import it.unive.ghidra.metrics.util.PathHelper;
import it.unive.ghidra.metrics.util.ZipHelper;
import it.unive.ghidra.metrics.util.ZipHelper.Zipper;

public class GMNCD extends GMBaseMetric<GMNCD, GMNCDProvider, GMNCDWinManager> {
	public static final String NAME = "NCD Similarity";
	
	private Path currentPath;
	
	public GMNCD(GMNCDProvider provider) {
		super(NAME, provider);
	}

	@Override
	public void init() {
		currentPath = new File(getProvider().getProgram().getDomainFile().getPathname()).toPath();		
	}
	
	protected void init(List<File> files) throws IOException {
		for (File file: files) {
			Path path = file.toPath();
			double ncd = calculateNCD(path);
			
			GMNCDKey key = new GMNCDKey(path.getFileName().toString());
			
			addMetricValue(GMMetricValue.ofNumeric(key, BigDecimal.valueOf(ncd)));
		}
	}

	@Override
	protected void functionChanged(Function fn) {
	
	}

	private double calculateNCD(Path path) throws IOException {
		return ncd(currentPath, path, ZipHelper::rzip);
	}
	

	private static double ncd(Path path1, Path path2, Zipper zipper) throws IOException {
		Double similarity = null;
		
		Path dir = Files.createTempDirectory("ghidra_metrics");
		try {			
			Path zip1 = zipper.zip(dir, path1);
			Long size1 = Files.size(zip1);

			Path zip2 = zipper.zip(dir, path2);
			Long size2 = Files.size(zip2);

			Path concatenated = PathHelper.concatPaths2(dir, path1, path2);
			Path zipConcat = zipper.zip(dir, concatenated);
			Long sizeConcat = Files.size(zipConcat);

			Double ncd = (1.00 * sizeConcat - Math.min(size1, size2)) / (1.00 * Math.max(size1, size2));
			similarity = 1.00 - ncd;
			
			PathHelper.deleteDirectory(dir);

		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}

		return similarity;
	}
}
