package it.unive.ghidra.metrics.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Comparator;

public class PathHelper {
	public static String getBasename(Path path) {
		String filename = path.getFileName().toString();
		String[] tokens = filename.split("\\.(?=[^\\.]+$)");
		return tokens[0];
	}
	
	public static Path concatPaths(Path dir, Path path1, Path path2) throws IOException {
		Path out = dir.resolve(Path.of(getBasename(path1) + "_" + getBasename(path2)));

		try (FileChannel outChannel = FileChannel.open(out, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {

			try (FileChannel in = FileChannel.open(path1, StandardOpenOption.READ)) {
				for (long p = 0, l = in.size(); p < l;)
					p += in.transferTo(p, l - p, outChannel);
			}

			try (FileChannel in = FileChannel.open(path2, StandardOpenOption.READ)) {
				for (long p = 0, l = in.size(); p < l;)
					p += in.transferTo(p, l - p, outChannel);
			}
		}
		return out;
	}
	
	public static Path concatPaths2(Path dir, Path path1, Path path2) throws IOException {
		Path out = dir.resolve(Path.of(getBasename(path1) + "_" + getBasename(path2)));
		
		try (
			BufferedReader buffReader1 = new BufferedReader(new InputStreamReader(new FileInputStream(path1.toFile()),"utf-8")); //Files.newBufferedReader(path1);
			BufferedReader buffReader2 = new BufferedReader(new InputStreamReader(new FileInputStream(path1.toFile()),"utf-8")); //Files.newBufferedReader(path2);
			BufferedWriter buffWriter  = Files.newBufferedWriter(out, StandardOpenOption.CREATE, StandardOpenOption.APPEND)
		) {
			char[] buffer = new char[1024];
			int count;

			while ((count = buffReader1.read(buffer)) > 0) {
				buffWriter.write(buffer, 0, count);
			}
			
			buffer = new char[1024];
			while ((count = buffReader2.read(buffer)) > 0) {
				buffWriter.write(buffer, 0, count);
			}
		}
		
		return out;
	}
	
	public static void deleteDirectory(Path path) throws IOException {  
		Files.walk(path)
		    .sorted(Comparator.reverseOrder())
		    .map(Path::toFile)
		    .forEach(File::delete);
	}

}
