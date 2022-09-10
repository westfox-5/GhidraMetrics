package ghidrametrics.serialize;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import ghidrametrics.GhidraMetricsExporter;
import ghidrametrics.base.BaseMetricWrapper;

public abstract class Serializer {
	
	public static Serializer of(GhidraMetricsExporter.Type type) {
		if (type == GhidraMetricsExporter.Type.JSON) return new JSONSerializer();
		return null;
	}
	
	private Stream<String> lines;
	private final GhidraMetricsExporter.Type type;
	
	protected Serializer(GhidraMetricsExporter.Type type) {
		this.type = type;
	}
	
	protected abstract <V> StringBuilder serializeWrapper(BaseMetricWrapper wrapper);
	
	public Serializer serialize(BaseMetricWrapper wrapper) throws IOException {
		StringBuilder sb = serializeWrapper(wrapper);
		
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
	
	public GhidraMetricsExporter.Type getType() {
		return type;
	}

}