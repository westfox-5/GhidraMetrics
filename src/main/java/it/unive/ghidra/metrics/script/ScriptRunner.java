package it.unive.ghidra.metrics.script;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
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
		
		sr.addArg(GMScriptArgumentKey.METRIC, args[0]);
		sr.addArg(GMScriptArgumentKey.EXPORT, args[1]);
		String input = args[2];

		if (args.length > 3) {
			sr.addArg(GMScriptArgumentKey.EXPORT_DIR, args[3]);
		}
		
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
		
		if ( sr.runGhidraHeadlessAnalyzer(pathsToProcess) ) {
			System.out.println("All executions terminated successfully.");
		} else {
			System.out.println("Some executions failed.");
		}
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
	
	private final boolean runGhidraHeadlessAnalyzer(List<Path> pathsToProcess) throws IOException, InterruptedException {
		File logFile = generateLogFile();
		
		boolean ok = true;
		
		System.out.println("Log generated in: " + absolute(logFile));
		System.out.println();
		
		for (Path executable: pathsToProcess) {
			File errTempFile = Files.createTempFile("gm_scriptrunner_err_", null).toFile();
			List<String> commands = generateCommands(executable);

			ProcessBuilder pb = new ProcessBuilder();			
			pb.command(commands);
			
			pb.redirectOutput(Redirect.appendTo(logFile));
			pb.redirectError(Redirect.appendTo(errTempFile));

			System.out.println("> Processing file: " + absolute(executable));
			System.out.println(pb.command().stream().collect(Collectors.joining(" ")));
			
			Process process = pb.start();
			boolean success = process.waitFor(20, TimeUnit.SECONDS);
			System.out.println("Checking errors...");
			boolean hasErrors = checkErrors(errTempFile);
			
			if (success && !hasErrors) {
				System.out.println("OK");
				errTempFile.deleteOnExit();
			} else {
				System.out.println("KO: log generated in: " + absolute(errTempFile));
				ok = false;
			}
		}
		
		return ok;
	}

	private File generateLogFile() {
		File logFile = new File(projectPath.toFile(), "ScriptRunner-"+(new SimpleDateFormat("ddMMyyyHHmmsss").format(new Date()))+".log");
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
	
	private String absolute(File file) {
		return file.getAbsolutePath();
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
	
	private boolean checkErrors(File tempFile) throws IOException {
		try (BufferedReader br = new BufferedReader(new FileReader(tempFile))) {
	        String line;
	        while ((line = br.readLine()) != null) {
	            if (line.startsWith("ERROR")) 
	            	return true;
	            if (line.contains("exception") || line.contains("Exception"))
	            	return true;
	        }
		}
		return false;
	}

}
