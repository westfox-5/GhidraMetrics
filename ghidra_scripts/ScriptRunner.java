
import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import it.unive.ghidra.metrics.script.GMScriptArgumentContainer.GMScriptArgumentKey;

public class ScriptRunner {
	
	private static final String SCRIPT_NAME = "GhidraMetricsScript";	
	private static final String DEFAULT_PRJ_NAME = "GhidraMetrics";


	/**
	 * Usage:
	 * RunGhidraScript <metric name> <export type> <input file or directory>
	 * 
	 */
	public static void main(String[] args) throws Exception {
		
		ScriptRunner sr = new ScriptRunner();
		
		String input = args[2];
		
		sr.addArg(GMScriptArgumentKey.METRIC, args[0]);
		sr.addArg(GMScriptArgumentKey.EXPORT, args[1]);
		
		Path inPath = Path.of(input);
		List<Path> pathsToProcess = null;
		
		if (inPath.toFile().isDirectory()) {
			
			try (Stream<Path> walk = Files.walk(inPath)) {
				pathsToProcess = walk.filter(f -> Files.isExecutable(f) && !Files.isDirectory(f))
					.collect(Collectors.toList());
			}
			
		} else {
			if (Files.isExecutable(inPath)) {
				pathsToProcess = Collections.singletonList( inPath );
			}
		}
		
		
		sr.runGhidraHeadlessAnalyzer(pathsToProcess);
		
		System.out.println("Terminated.");
	}

	
	
	private Path projectPath;
	private Path ghidraAnalyzeHeadlessPath;
	private final Map<GMScriptArgumentKey, String> scriptArgs = new HashMap<>();

	public ScriptRunner() throws Exception { 
		init();
	}
	
	private void init() throws Exception {
		{
			String USER_HOME = System.getenv("HOME");
			Path projectPath = Path.of(USER_HOME, DEFAULT_PRJ_NAME);
			if (!Files.exists(projectPath, LinkOption.NOFOLLOW_LINKS)) {
				Files.createDirectory(projectPath);
			}
			this.projectPath = projectPath;	
		}
		
		
		{
			String GHIDRA_HOME = System.getenv("GHIDRA_HOME");
			if (GHIDRA_HOME == null)
				throw new Exception("Missing GHIDRA_HOME env. variable");
			
			this.ghidraAnalyzeHeadlessPath = Path.of(GHIDRA_HOME, "support", "analyzeHeadless");
		}
	}
	
	public void addArg(GMScriptArgumentKey key, String value) {
		scriptArgs.put(key, value);
	}
	
	private final void runGhidraHeadlessAnalyzer(List<Path> pathsToProcess) throws IOException, InterruptedException {
		File logFile = generateLogFile();
		
		System.out.println("Log generated in: " + logFile.getAbsolutePath());
		
		for (Path executable: pathsToProcess) {
			ProcessBuilder pb = new ProcessBuilder();
			
			pb.command( generateCommands(executable) );
			Redirect redirect = Redirect.appendTo(logFile);
			pb.redirectOutput(redirect);
			pb.redirectError(redirect);

			System.out.println("> Processing file: " + absolute(executable));
			System.out.println(pb.command().stream().collect(Collectors.joining(" ")));
			
			Process process = pb.start();
			
			if (process.waitFor(20, TimeUnit.SECONDS)) {
				System.out.println("OK");
			} else {
				System.out.println("KO");
			}
		}
	}

	private File generateLogFile() {
		File logFile = new File(projectPath.toFile(), "ScriptRunner-"+(new SimpleDateFormat("ddMMyyy-HHmmsss").format(new Date()))+".log");
		return logFile;
	}
	
	private List<String> generateCommands(Path executable) {
		List<String> commands = new ArrayList<>();
		
		/* ----- */
		commands.add(absolute(ghidraAnalyzeHeadlessPath));
		/* ----- */
		commands.add(absolute(projectPath));
		commands.add(DEFAULT_PRJ_NAME);
		/* ----- */
		commands.add("-import");
		commands.add(executable.toAbsolutePath().toString());
		/* ----- */
		commands.add("-postScript");
		commands.add(SCRIPT_NAME);
		commands.addAll(serializeScriptArgs());
		/* ----- */
		commands.add("-deleteProject");
		commands.add("-analysisTimeoutPerFile");
		commands.add("10");
		/* ----- */
		
		return commands;
	}
	
	private String absolute(Path path) {
		return path.toAbsolutePath().toString();
	}

	private List<String> serializeScriptArgs() {
		return scriptArgs.keySet().parallelStream().map( k -> serializeScriptArgs(k)).collect(Collectors.toList());
	}

	private String serializeScriptArgs(GMScriptArgumentKey key) {
		String value = scriptArgs.get(key);
		if (value != null) {
			return key.getKey()+"="+value;
		}
		return key.getKey();
	}
}
