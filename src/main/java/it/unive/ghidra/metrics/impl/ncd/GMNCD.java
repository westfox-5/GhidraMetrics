package it.unive.ghidra.metrics.impl.ncd;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import ghidra.app.util.exporter.BinaryExporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import it.unive.ghidra.metrics.base.GMAbstractMetric;
import it.unive.ghidra.metrics.util.GMTaskMonitor;
import it.unive.ghidra.metrics.util.PathHelper;
import it.unive.ghidra.metrics.util.ZipHelper;

public class GMNCD extends GMAbstractMetric<GMNCD, GMNCDProvider, GMNCDWinManager> {
	public static final String NAME = "NCD Similarity";

	private static final String DEFAULT_DIR = "ghidra_metrics_";
	private static final String DEFUALT_PREFIX = "ghidra_ncd_";

	private Path tmpDir;

	private Path exportPath;
	private Path zipPath;
	private Long zipSize;

	private final ZipHelper.Zipper zipper = ZipHelper::rzip;

	public GMNCD(GMNCDProvider provider) {
		super(NAME, provider);
	}

	@Override
	public boolean init() {
		try {
			this.tmpDir = Files.createTempDirectory(DEFAULT_DIR);
			this.exportPath = Files.createTempFile(tmpDir, DEFUALT_PREFIX, null);

			GMTaskMonitor monitor = new GMTaskMonitor();

			DomainObject immutableDomainObject = getProvider().getProgram().getDomainFile()
					.getImmutableDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);

			BinaryExporter binaryExporter = new BinaryExporter();
			binaryExporter.export(exportPath.toFile(), immutableDomainObject, null, null);

			this.zipPath = zipper.zip(tmpDir, exportPath);
			this.zipSize = Files.size(zipPath);

		} catch (IOException x) {
			x.printStackTrace();

			if (!provider.isHeadlessMode()) {
				Msg.showError(this, provider.getPlugin().getProvider().getComponent(), "Error",
						"If you see this error, it is very likely that you do not have 'rzip' installed in your system. Please procede to installation in order to continue using this plugin.");
			}

			return false;
		} catch (VersionException x) {
			x.printStackTrace();
			return false;
		} catch (CancelledException x) {
			x.printStackTrace();
			return false;
		} catch (ExporterException x) {
			x.printStackTrace();
			return false;
		}

		return true;
	}

	protected void compute(List<File> files) throws IOException {
		for (File file : files) {
			Path path = file.toPath();
			double ncd = ncd(path);

			GMNCDKey key = new GMNCDKey(path.getFileName().toString());
			createMetricValue(key, ncd);
		}
	}

	@Override
	protected void functionChanged(Function fn) {

	}

	private double ncd(Path path) throws IOException {
		Double similarity = null;

		try {
			Path zipPath2 = zipper.zip(tmpDir, path);
			Long zipSize2 = Files.size(zipPath2);

			Path concatPath = PathHelper.concatPaths2(tmpDir, exportPath, path);
			Path zipConcat = zipper.zip(tmpDir, concatPath);
			Long zipSizeConcat = Files.size(zipConcat);

			Double ncd = (1.00 * zipSizeConcat - Math.min(zipSize, zipSize2)) / (1.00 * Math.max(zipSize, zipSize2));
			similarity = 1.00 - ncd;

		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}

		return similarity;
	}
}
