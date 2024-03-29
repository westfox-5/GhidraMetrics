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

	public static Path zip(Path dir, Path file) throws ZipException {
		Path zip = getZipPath(dir, file, ".zip");

		try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(zip.toFile()));
				ZipOutputStream zos = new ZipOutputStream(bos)) {
			try (FileInputStream fis = new FileInputStream(file.toFile())) {
				ZipEntry zipEntry = new ZipEntry(file.getFileName().toString());
				zos.putNextEntry(zipEntry);

				byte[] buffer = new byte[1024];
				int count;

				while ((count = fis.read(buffer)) > 0) {
					zos.write(buffer, 0, count);
				}
			} catch(IOException e) {
				throw new ZipException(e);
			}
		} catch(IOException e) {
			throw new ZipException(e);
		}

		return zip;
	}

	public static Path gzip(Path dir, Path file) throws ZipException {
		Path zip = getZipPath(dir, file, ".gzip");

		try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(zip.toFile()));
				GZIPOutputStream zos = new GZIPOutputStream(bos)) {
			try (FileInputStream fis = new FileInputStream(file.toFile())) {

				byte[] buffer = new byte[1024];
				int count;
				while ((count = fis.read(buffer)) > 0) {
					zos.write(buffer, 0, count);
				}

				zos.finish();
			} catch(IOException e) {
				throw new ZipException(e);
			}
		} catch(IOException e) {
			throw new ZipException(e);
		}

		return zip;
	}

	/**
	 * If 'rzip' program is not installed, an IOException will be thrown
	 * 
	 * @param dir
	 * @param file
	 * @return
	 * @throws IOException
	 */
	public static Path rzip(Path dir, Path file) throws ZipException {
		Path zip = getZipPath(dir, file, ".rzip");

		String[] cmd = new String[] { "rzip",
				"-9", 	// slowest but best compression
				"-k", 	// keep input file
				"-o", zip.toAbsolutePath().toString(),	 // OUTPUT
				file.toAbsolutePath().toString() 		// INPUT
		};

		ProcessBuilder builder = new ProcessBuilder();

		builder.directory(dir.toFile());
		builder.command(cmd);

		try {
			Process process = builder.start();
			int exitCode = process.waitFor();

			if (0 != exitCode) {
				throw new ZipException("rzip terminated with code: " + exitCode + ". Command: " + Arrays.asList(cmd).toString());
			}

		} catch (InterruptedException | IOException e) {
			throw new ZipException(e);
		}

		return zip;
	}

	private static Path getZipPath(Path dir, Path file, String ext) {
		String basename = PathHelper.getBasename(file);
		long uuid = UUID.randomUUID().getMostSignificantBits();
		return dir.resolve(Path.of(basename + "_" + uuid + ext));
	}
	
	public static class ZipException extends Exception {
		private static final long serialVersionUID = 1L;

		public ZipException() {
			super();
		}

		public ZipException(String message, Throwable cause) {
			super(message, cause);
		}

		public ZipException(String message) {
			super(message);
		}

		public ZipException(Throwable cause) {
			super(cause);
		}
	}
}