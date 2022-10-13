package it.unive.ghidra.metrics.util;

import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.UUID;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ZipHelper {

	@FunctionalInterface
	public static interface Zipper {
		Path zip(Path dir, Path path) throws IOException;
	}

	public static Path zip(Path dir, Path path) throws IOException {
		Path zip = getZipPath(dir, path, ".zip");

		try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(zip.toFile()));
				ZipOutputStream zos = new ZipOutputStream(bos)) {
			try (FileInputStream fis = new FileInputStream(path.toFile())) {
				ZipEntry zipEntry = new ZipEntry(path.getFileName().toString());
				zos.putNextEntry(zipEntry);

				byte[] buffer = new byte[1024];
				int count;

				while ((count = fis.read(buffer)) > 0) {
					zos.write(buffer, 0, count);
				}
			}
		}

		return zip;
	}

	public static Path gzip(Path dir, Path path) throws IOException {
		Path zip = getZipPath(dir, path, ".gzip");

		try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(zip.toFile()));
				GZIPOutputStream zos = new GZIPOutputStream(bos)) {
			try (FileInputStream fis = new FileInputStream(path.toFile())) {

				byte[] buffer = new byte[1024];
				int count;
				while ((count = fis.read(buffer)) > 0) {
					zos.write(buffer, 0, count);
				}

				zos.finish();

			}
		}

		return zip;
	}

	public static Path rzip(Path dir, Path path) throws IOException {
		Path zip = getZipPath(dir, path, ".rzip");

		String[] cmd = new String[] { "rzip",

				"-9", // slowest but best compression

				"-k", // keep input file

				"-o", zip.toAbsolutePath().toString(), // OUTPUT

				path.toAbsolutePath().toString() // INPUT
		};

		ProcessBuilder builder = new ProcessBuilder();

		builder.directory(dir.toFile());
		builder.command(cmd);

		Process process = builder.start();

		try {
			int exitCode = process.waitFor();
			if (0 != exitCode) {
				throw new RuntimeException(
						"rzip terminated with code: " + exitCode + ". Command: " + Arrays.asList(cmd).toString());
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		return zip;
	}

	private static Path getZipPath(Path dir, Path path, String ext) {
		String basename = PathHelper.getBasename(path);
		long uuid = UUID.randomUUID().getMostSignificantBits();
		return dir.resolve(Path.of(basename + "_" + uuid + ext));
	}
}