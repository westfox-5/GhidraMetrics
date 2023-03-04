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
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import it.unive.ghidra.metrics.impl.GhidraMetricsFactory;
import it.unive.ghidra.metrics.util.StringUtils;

public class GMScriptRunner {

	private static final String SCRIPT_NAME = "GhidraMetricsScript";
	private static final String DEFAULT_PRJ_NAME = "GhidraMetrics";

	public static void main(String[] args) throws Exception {
		doWelcome();

		CommandLine cmd = parseArgs(args);
		if (cmd == null) {
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
		System.out.println("Ghidra Metrics - compute code metric on native code");
		System.out.println();
	}

	private static void printHelp(Options options) {
		HelpFormatter formatter = new HelpFormatter();
		formatter.setWidth(300);
		formatter.printHelp("GMScriptRunner", options, true);
	}

	private static String prettyPrintValues(Collection<String> values) {
		return "[" + values.stream().sorted().collect(Collectors.joining(", ")) + "]";
	}

	private static Options createOptions() {
		Options options = new Options();

		Option metricName = new Option("m", "metric-name", true,
				"metric names " + prettyPrintValues(GhidraMetricsFactory.allMetrics()));
		metricName.setRequired(true);
		options.addOption(metricName);

		Option exportType = new Option("e", "export-type", true,
				"export types " + prettyPrintValues(GhidraMetricsFactory.allFileFormats()));
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

		Option inputRecursive = new Option("r", "recursive", false,
				"perform analysis over all executable files recursively, otherwise only top-level ones");
		inputRecursive.setRequired(false);
		options.addOption(inputRecursive);

		Option logger = new Option("l", "log", true,
				"logger output file. If not provided, the output will be saved in the project directory");
		logger.setRequired(false);
		options.addOption(logger);

		Option verbose = new Option("v", "verbose", false, "enable verbose mode");
		verbose.setRequired(false);
		options.addOption(verbose);

		Option similarityInput = new Option(null, "similarity-input", true,
				"path to an executable file to compare with current input in the similarity metric");
		similarityInput.setRequired(false);
		options.addOption(similarityInput);

		Option similarityZipper = new Option(null, "similarity-zipper", true,
				"zipper functions " + prettyPrintValues(GhidraMetricsFactory.allZippers()));
		similarityZipper.setRequired(false);
		options.addOption(similarityZipper);

		return options;
	}

	private Path projectPath;
	private Path ghidraAnalyzeHeadlessPath;
	private final Map<GMScriptArgument<?>, String> scriptArgs = new HashMap<>();

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
		addGhidraArg(GMScriptArgument.ARG_METRIC, cmd.getOptionValue("metric-name"));
		addGhidraArg(GMScriptArgument.ARG_EXPORT, cmd.getOptionValue("export-type"));

		if (cmd.hasOption("function-name")) {
			addGhidraArg(GMScriptArgument.ARG_FUNCTION, cmd.getOptionValue("function-name", null));
		}

		if (cmd.hasOption("output")) {
			addGhidraArg(GMScriptArgument.ARG_EXPORT_DIR, cmd.getOptionValue("output", null));
		}

		if (cmd.hasOption("similarity-input")) {
			Path similarityInput = Path.of(cmd.getOptionValue("similarity-input"));
			addGhidraArg(GMScriptArgument.ARG_SIMILARITY_INPUT, absolute(similarityInput));
		}

		if (cmd.hasOption("similarity-zipper")) {
			addGhidraArg(GMScriptArgument.ARG_SIMILARITY_ZIPPER, cmd.getOptionValue("similarity-zipper"));
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

	public final void addGhidraArg(GMScriptArgument<?> arg, String value) {
		scriptArgs.put(arg, value);
	}

	public final void run() throws IOException {
		List<Path> pathsToProcess = getExecutableFilesInPath(inPath);
		runGhidraHeadlessAnalyzer(pathsToProcess);
	}

	private final boolean runGhidraHeadlessAnalyzer(List<Path> inputs) throws IOException {
		File logFile = generateLogFile();

		System.out.println("> Log generated in: " + absolute(logFile));
		System.out.println();

		List<ProcessBuilder> pbs = new ArrayList<>();
		for (Path exe : inputs) {
			pbs.add(createProcessBuilder(exe, logFile));
		}

		boolean ok = true;

		for (ProcessBuilder pb : pbs) {
			System.out.println("> Processing file: " + pb.environment().get("EXE"));
			if (verbose)
				System.out.println(pb.command().stream().collect(Collectors.joining(" ")));

			Process process = pb.start();
			File errFile = pb.redirectError().file();

			int exitValue = 0;
			try {
				exitValue = process.waitFor();
				if (verbose)
					System.out.println("> Process exited with value: " + exitValue);

			} catch (InterruptedException e) {
				Files.writeString(errFile.toPath(), e.getMessage(), StandardOpenOption.APPEND);
			}

			if (exitValue == 0) {
				System.out.println("> OK - output saved to: " + getOutputFullPath(pb.environment().get("EXE")));
				errFile.deleteOnExit();
			} else {
				System.out.println("> Checking errors...");
				List<String> exceptionsInLog = getExceptionsInFile(errFile, 5);

				if (exceptionsInLog == null) {
					System.err.println("> Analysis timed out!");
				} else {
					System.out.println("> Error log generated in: " + absolute(errFile));
					if (verbose) {
						System.out.println("> Found errors (check the error log for better understanding):");
						for (String exception : exceptionsInLog) {
							System.err.println(exception);
						}
					}
				}

				ok = false;
			}
		}

		if (ok) {
			System.out.println();
			System.out.println("> All executions terminated successfully!");
		} else {
			System.err.println();
			System.err.println("> Some executions failed.");
		}

		return ok;
	}

	private String getOutputFullPath(String executable) {
		Path executablePath = Path.of(executable);
		
		String outDir = StringUtils.fillIfEmpty(scriptArgs.get(GMScriptArgument.ARG_EXPORT_DIR), outDir = executablePath.getParent().toAbsolutePath().toString());
		String outFile = StringUtils.title(scriptArgs.get(GMScriptArgument.ARG_METRIC)) + "_" + executablePath.getFileName();
		String ext = GhidraMetricsFactory.getFileFormat(scriptArgs.get(GMScriptArgument.ARG_EXPORT)).getExtension();
		
		return outDir + File.separator + outFile + "." + ext;
	}

	private ProcessBuilder createProcessBuilder(Path executable, File logFile) throws IOException {
		File errTempFile = Files.createTempFile("gm_scriptrunner_err_", null).toFile();
		List<String> commands = generateGhidraCommands(executable);

		ProcessBuilder pb = new ProcessBuilder();
		pb.command(commands);

		pb.redirectOutput(Redirect.appendTo(logFile));
		pb.redirectError(Redirect.appendTo(errTempFile));

		pb.environment().put("EXE", absolute(executable));

		return pb;
	}

	private File generateLogFile() {
		if (logPath != null)
			return logPath.toFile();

		// default log file
		File logFile = new File(projectPath.toFile(),
				"GMScriptRunner-" + (new SimpleDateFormat("ddMMyyyHHmmsss").format(new Date())) + ".log");
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
		commands.add("30");
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
		return scriptArgs.keySet().parallelStream().map(k -> serializeScriptArgs(k)).collect(Collectors.toList());
	}

	private String serializeScriptArgs(GMScriptArgument<?> arg) {
		String value = scriptArgs.get(arg);
		if (value != null) {
			return arg.getName() + "=" + value;
		}
		return arg.getName();
	}

	private final List<String> getExceptionsInFile(File tempFile, int maxLines) throws IOException {
		List<String> exceptions = new ArrayList<>();
		try (BufferedReader br = new BufferedReader(new FileReader(tempFile))) {
			String line;
			int count = 0;
			while ((line = br.readLine()) != null && count < maxLines) {
				if (line.contains("exception") || line.contains("Exception")) {
					exceptions.add(line);
					count++;
				} else if (line.startsWith("ERROR")) {
					exceptions.add(line);
					count++;
				}
			}
		}
		return exceptions.isEmpty() ? null : exceptions;
	}

	private final List<Path> getExecutableFilesInPath(Path input) throws IOException {
		List<Path> list = new ArrayList<>();

		if (input.toFile().isDirectory()) {
			int maxDepth = isRecursive() ? Integer.MAX_VALUE : 1;
			try (Stream<Path> walk = Files.walk(input, maxDepth)) {
				list = walk.filter(f -> Files.isExecutable(f) && !Files.isDirectory(f)).collect(Collectors.toList());
			}
		} else if (Files.isExecutable(input)) {
			list = Collections.singletonList(input);
		}

		return list;
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
