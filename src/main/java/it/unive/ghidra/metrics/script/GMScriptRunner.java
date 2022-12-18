package it.unive.ghidra.metrics.script;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import it.unive.ghidra.metrics.script.GMScriptArgumentContainer.GMScriptArgumentKey;

public class GMScriptRunner {
	
	private static final String SCRIPT_NAME = "GhidraMetricsScript";	
	private static final String DEFAULT_PRJ_NAME = "GhidraMetrics";
	
	public static void main(String[] args) throws Exception {		
		doWelcome();

		CommandLine cmd = parseArgs(args);
		if ( cmd == null ) {
			System.exit(1);
		}
		
		GMScriptRunner sr = new GMScriptRunner(cmd);
		sr.run();
		
		System.exit(0);
	}
	
	private static CommandLine parseArgs(String[] args) {
		CommandLine cmd = null; 
		
		Options options = createOptions();
        CommandLineParser parser = new DefaultParser();
        
        try {
        	cmd = parser.parse(options, args);
        	
        } catch (ParseException e) {
        	System.out.println(e.getMessage());
        	printHelp(options);
        }
		
        return cmd;
	}

	public static void doWelcome() { 
		System.out.println();
		System.out.println("    /$$$$$$  /$$       /$$       /$$                                /$$      /$$             /$$               /$$                     ");
		System.out.println("   /$$__  $$| $$      |__/      | $$                               | $$$    /$$$            | $$              |__/                    ");
		System.out.println("  | $$  \\__/| $$$$$$$  /$$  /$$$$$$$  /$$$$$$  /$$$$$$             | $$$$  /$$$$  /$$$$$$  /$$$$$$    /$$$$$$  /$$  /$$$$$$$  /$$$$$$$");
		System.out.println("  | $$ /$$$$| $$__  $$| $$ /$$__  $$ /$$__  $$|____  $$            | $$ $$/$$ $$ /$$__  $$|_  $$_/   /$$__  $$| $$ /$$_____/ /$$_____/");
		System.out.println("  | $$|_  $$| $$  \\ $$| $$| $$  | $$| $$  \\__/ /$$$$$$$            | $$  $$$| $$| $$$$$$$$  | $$    | $$  \\__/| $$| $$      |  $$$$$$ ");
		System.out.println("  | $$  \\ $$| $$  | $$| $$| $$  | $$| $$      /$$__  $$            | $$\\  $ | $$| $$_____/  | $$ /$$| $$      | $$| $$       \\____  $$");
		System.out.println("  |  $$$$$$/| $$  | $$| $$|  $$$$$$$| $$     |  $$$$$$$            | $$ \\/  | $$|  $$$$$$$  |  $$$$/| $$      | $$|  $$$$$$$ /$$$$$$$/");
		System.out.println("   \\______/ |__/  |__/|__/ \\_______/|__/      \\_______/            |__/     |__/ \\_______/   \\___/  |__/      |__/ \\_______/|_______/ ");
		System.out.println();
	}
	
	private static void printHelp(Options options) {
		HelpFormatter formatter = new HelpFormatter();
    	formatter.setWidth(300);
    	formatter.printHelp("GMScriptRunner", options, true);		
	}

	private static Options createOptions() {
		Options options = new Options();		
		
		Option metricName = new Option("m", "metric-name", true, "metric name [halstead, ncd, mccabe]");
		metricName.setRequired(true);
        options.addOption(metricName);
        
		Option exportType = new Option("e", "export-type", true, "export type [txt, json]");
		exportType.setRequired(true);
        options.addOption(exportType);
        
        Option input = new Option("i", "input", true, "input file or directory");
        input.setRequired(true);
        options.addOption(input);
        
        Option functionName = new Option("f", "function-name", true, "function name");
        functionName.setRequired(false);
        options.addOption(functionName);
        
        Option output = new Option("o", "output", true, "output directory");
        output.setRequired(false);
        options.addOption(output);
        
        Option inputRecursive = new Option("r", "recursive", false, "perform analysis over all exe files recursively, otherwise only top-level files");
        inputRecursive.setRequired(false);
        options.addOption(inputRecursive);
        
        Option logger = new Option("l", "log", true, "log output file. If not provided, it will be created a file in the project directory");
        logger.setRequired(false);
        options.addOption(logger);
        
        Option verbose = new Option("v", "verbose", false, "enable verbose mode");
        verbose.setRequired(false);
        options.addOption(verbose);
        
        return options;
	}

	private Path projectPath;
	private Path ghidraAnalyzeHeadlessPath;
	private final Map<GMScriptArgumentKey, String> scriptArgs = new HashMap<>();
	
	private boolean recursive;
	private boolean verbose;

	private Path logPath;
	private Path inPath;
	
	public GMScriptRunner(CommandLine cmd) throws Exception { 
		init();
		addCommands(cmd);
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
	
	private void addCommands(CommandLine cmd) {
		addGhidraArg(GMScriptArgumentKey.METRIC, cmd.getOptionValue("metric-name"));
		addGhidraArg(GMScriptArgumentKey.EXPORT, cmd.getOptionValue("export-type"));
		
		if (cmd.hasOption("function-name")) {
			addGhidraArg(GMScriptArgumentKey.FUNCTION, cmd.getOptionValue("function-name", null));
		}
		
		if (cmd.hasOption("output")) {
			addGhidraArg(GMScriptArgumentKey.EXPORT_DIR, cmd.getOptionValue("output", null));
		}

		if (cmd.hasOption("recursive")) {
			setRecursive(true);
		}
		
		if (cmd.hasOption("verbose")) {
			setVerbose(true);
		}
		
		if (cmd.hasOption("log")) {
			File logFile = new File(cmd.getOptionValue("log"));
			if (logFile.exists()) {
				logFile.delete();
			}
			this.logPath = logFile.toPath();
		}
		
		String input = cmd.getOptionValue("input");
		this.inPath = Path.of(input);

	}
	
	public final void addGhidraArg(GMScriptArgumentKey key, String value) {
		scriptArgs.put(key, value);
	}
	

	public final void run() throws IOException {
		List<Path> pathsToProcess = null;
		
		if (inPath.toFile().isDirectory()) {
			int maxDepth = isRecursive() ? Integer.MAX_VALUE : 1;
			try (Stream<Path> walk = Files.walk(inPath, maxDepth)) {
				pathsToProcess = walk.filter(f -> Files.isExecutable(f) && !Files.isDirectory(f))
					.collect(Collectors.toList());
			}
		} else if (Files.isExecutable(inPath)) {
			pathsToProcess = Collections.singletonList( inPath );
		}
		
		runGhidraHeadlessAnalyzer(pathsToProcess);
	}

	
	private final boolean runGhidraHeadlessAnalyzer(List<Path> pathsToProcess) throws IOException {
		File logFile = generateLogFile();
		
		boolean ok = true;
		
		System.out.println("> Log generated in: " + absolute(logFile));
		System.out.println();
		
		for (Path executable: pathsToProcess) {
			File errTempFile = Files.createTempFile("gm_scriptrunner_err_", null).toFile();
			List<String> commands = generateGhidraCommands(executable);

			ProcessBuilder pb = new ProcessBuilder();			
			pb.command(commands);
			
			pb.redirectOutput(Redirect.appendTo(logFile));
			pb.redirectError(Redirect.appendTo(errTempFile));

			System.out.println("> Processing file: " + absolute(executable));
			if (isVerbose()) System.out.println(pb.command().stream().collect(Collectors.joining(" ")));
			
			Process process = pb.start();
			boolean success = false;
			boolean hasErrors = false;
			
			try {
				success = process.waitFor(20, TimeUnit.SECONDS);
				if (isVerbose()) System.out.println("> Checking errors...");
				hasErrors = checkErrors(errTempFile);

			} catch (InterruptedException e) {
				e.printStackTrace();
				Files.writeString(errTempFile.toPath(), e.getMessage(), StandardOpenOption.APPEND);
			}
			
			if (success && !hasErrors) {
				System.out.println("> OK");
				errTempFile.deleteOnExit();
			} else {
				System.out.println("> KO: log generated in: " + absolute(errTempFile));
				ok = false;
			}
		}
		
		if (ok) {
			System.out.println();
			System.out.println("> All executions terminated successfully.");
		} else {
			System.out.println();
			System.out.println("> Some executions failed.");
		}
		
		return ok;
	}

	private File generateLogFile() {
		if (logPath != null)
			return logPath.toFile();
		
		// default log file
		File logFile = new File(projectPath.toFile(), "GMScriptRunner-"+(new SimpleDateFormat("ddMMyyyHHmmsss").format(new Date()))+".log");
		return logFile;
	}
	
	private List<String> generateGhidraCommands(Path executable) {
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
	
	private final String absolute(File file) {
		return file.getAbsolutePath();
	}
	
	private final String absolute(Path path) {
		return path.toAbsolutePath().toString();
	}

	private final List<String> serializeScriptArgs() {
		return scriptArgs.keySet().parallelStream().map( k -> serializeScriptArgs(k)).collect(Collectors.toList());
	}

	private String serializeScriptArgs(GMScriptArgumentKey key) {
		String value = scriptArgs.get(key);
		if (value != null) {
			return key.getKey()+"="+value;
		}
		return key.getKey();
	}
	
	private final boolean checkErrors(File tempFile) throws IOException {
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

	public boolean isRecursive() {
		return recursive;
	}

	public void setRecursive(boolean recursive) {
		this.recursive = recursive;
	}

	public boolean isVerbose() {
		return verbose;
	}

	public void setVerbose(boolean verbose) {
		this.verbose = verbose;
	}	
}
