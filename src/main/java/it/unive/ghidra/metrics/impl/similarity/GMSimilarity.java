package it.unive.ghidra.metrics.impl.similarity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import ghidra.app.util.exporter.ExporterException;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import it.unive.ghidra.metrics.base.GMBaseMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMeasure;
import it.unive.ghidra.metrics.util.GMTaskMonitor;
import it.unive.ghidra.metrics.util.PathHelper;
import it.unive.ghidra.metrics.util.ZipHelper;
import it.unive.ghidra.metrics.util.ZipHelper.ZipException;

public class GMSimilarity extends GMBaseMetric<GMSimilarity, GMSimilarityManager, GMSimilarityWinManager> {
	public static final String NAME = "Similarity";
	public static final String LOOKUP_NAME = "similarity";

	private static final String[] 
			TABLE_COLUMNS = { "File", "NCD Similarity" };
	private static final java.util.function.Function<GMMeasure<?>, Object[]> 
			TABLE_ROWS_FUNCTION = measure -> new Object[] {
				measure.getKey().getName(), 
				measure.getValue()
			};
	
	private static final String TEMP_DIR_PREFIX = "ghidra_metrics_";
	private Path TEMP_DIR;

	private final ZipHelper.Zipper zipper = ZipHelper::rzip;

	public GMSimilarity(GMSimilarityManager manager) {
		super(NAME, manager);
	}

	@Override
	public boolean init() {
		try {
			TEMP_DIR = Files.createTempDirectory(TEMP_DIR_PREFIX);
			
			Msg.info(this, "temp directory created: "+ TEMP_DIR.toAbsolutePath().toString());
			/* getManager().getPlugin().getTool().getProject(); */
						
		} catch (IOException x) {
			manager.printException(x);
			return false;
		}

		return true;
	}


	protected void createMeasures(List<Path> toCompute) throws ZipException, ExporterException, IOException {
		Path zipPath;
		try {
			zipPath = zipToTempFile(getExecutablePath(getManager().getProgram()));
		} catch (ZipException x) {
			manager.printException(new Exception("If you see this error, it is very likely that you do not have 'rzip' installed in your system."
					+ " Please procede to installation in order to continue using this plugin.", x));
			return;
		}

		Long zipSize = Files.size(zipPath);
		
		for (Path path: toCompute) {
			// data for other programs
			Program otherProgram = importNewProgram(path);
			otherProgram.setTemporary(true);
			
			Path otherZipPath = zipToTempFile(getExecutablePath(otherProgram));
			Long otherZipSize = Files.size(otherZipPath);
			
			Path concatPath = PathHelper.concatPaths(TEMP_DIR, zipPath, otherZipPath);
			Path concatZipPath = zipper.zip(TEMP_DIR, concatPath);
			Long concatZipSize = Files.size(concatZipPath);

			Double ncd = (1.00 * concatZipSize - Math.min(zipSize, otherZipSize)) / (1.00 * Math.max(zipSize, otherZipSize));

			GMSimilarityKey key = new GMSimilarityKey(path);
			createMeasure(key, 1-ncd);
			
			Files.deleteIfExists(otherZipPath);
			Files.deleteIfExists(concatPath);
			Files.deleteIfExists(concatZipPath);
		}
		
		Files.deleteIfExists(zipPath);
		
	}

	@Override
	protected void functionChanged(Function fn) {

	}
	
	private Path zipToTempFile(Path file) throws ZipException {
		return zipper.zip(TEMP_DIR, file);
	}
	
	private Path getExecutablePath(Program program) throws IOException {
		/*
		Path source = Path.of(getManager().getProgram().getExecutablePath());
		Path target = TEMP_DIR.toAbsolutePath().resolve(source.getFileName());
		Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
		*/
		return Path.of(getManager().getProgram().getExecutablePath());
	}
	
	private Program importNewProgram(Path path) throws IOException {
		GMTaskMonitor monitor = new GMTaskMonitor();
		try {
			return AutoImporter.importByUsingBestGuess(path.toFile(), (DomainFolder)null, this, new MessageLog(), monitor);
		} catch (CancelledException | DuplicateNameException | InvalidNameException | VersionException e) {
			manager.printException(e);
		}
		
		return null;
/*
		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
		analysisManager.startAnalysis(monitor);
		analysisManager.waitForAnalysis(null, monitor); // waits for all analysis to complete
		return analysisManager.getProgram();
*/
	}
	
	@Override
	public String[] getTableColumns() {
		return TABLE_COLUMNS;
	}

	@Override
	public java.util.function.Function<GMMeasure<?>, Object[]> getTableRowFn() {
		return TABLE_ROWS_FUNCTION;
	}

}
