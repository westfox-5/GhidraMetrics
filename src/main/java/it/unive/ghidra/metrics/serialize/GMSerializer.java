package it.unive.ghidra.metrics.serialize;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import it.unive.ghidra.metrics.GMExporter;
import it.unive.ghidra.metrics.base.GMetric;

public abstract class GMSerializer {
	
	public static GMSerializer of(GMExporter.Type type) {
		if (type == GMExporter.Type.JSON) return new GMJSONSerializer();
		return null;
	}
	
	private Stream<String> lines;
	private final GMExporter.Type type;
	
	protected GMSerializer(GMExporter.Type type) {
		this.type = type;
	}
	
	protected abstract <V> StringBuilder serializeMetric(GMetric metric);
	
	public GMSerializer serialize(GMetric metric) throws IOException {
		StringBuilder sb = serializeMetric(metric);
		
		this.lines = Pattern.compile(System.lineSeparator()).splitAsStream(sb);
		
		return this;
	}
	
	public void toFile(Path dest) throws IOException {
		if (lines != null) {
			lines.map(line -> line + System.lineSeparator()).forEachOrdered(line -> writeLineToFile(dest, line));
		}
	}

	private void writeLineToFile(final Path path, final String line) {
		try {
			Files.writeString(path, line, StandardOpenOption.APPEND);
	
		// TODO handle these exceptions more gracefully
		} catch (IOException x) {
			x.printStackTrace();
		}				
	}
	
	public GMExporter.Type getType() {
		return type;
	}

}