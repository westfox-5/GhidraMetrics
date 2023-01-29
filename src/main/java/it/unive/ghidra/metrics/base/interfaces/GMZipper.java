package it.unive.ghidra.metrics.base.interfaces;

import java.nio.file.Path;

import it.unive.ghidra.metrics.util.ZipHelper.ZipException;

@FunctionalInterface
public interface GMZipper {
	Path zip(Path dir, Path file) throws ZipException;
}