// SPDX-License-Identifier: Apache-2.0

use glob::{MatchOptions, Pattern};
use itertools::Itertools;
use std::env;
use std::path::{Path, PathBuf};

macro_rules! target_os {
    ($os:expr) => {
        cfg!(target_os = $os)
    };
}

macro_rules! target_env {
    ($os:expr) => {
        cfg!(target_env = $os)
    };
}

macro_rules! test {
    () => {
        cfg!(test)
    };
}

//================================================
// Commands
//================================================

//================================================
// Search Directories
//================================================

const DIRECTORIES_LINUX: &[&str] = &[
    "/usr/local/lib*/*/*",
    "/usr/local/lib*/*",
    "/usr/local/lib*",
    "/usr/lib*/*/*",
    "/usr/lib*/*",
    "/usr/lib*",
];

const DIRECTORIES_MACOS: &[&str] = &[];

///
/// The boolean indicates whether the directory pattern should be used when
/// compiling for an MSVC target environment.
const DIRECTORIES_WINDOWS: &[(&str, bool)] = &[("C:\\MSYS*\\MinGW*\\lib", false)];

const DIRECTORIES_LOCAL: &[&str] = &["lib*/*/*", "lib*/*", "lib*"];

//================================================
// Searching
//================================================

/// Finds the files in a directory that match one or more filename glob patterns
/// and returns the paths to and filenames of those files.
fn search_directory(directory: &Path, filenames: &[String]) -> Vec<(PathBuf, String)> {
    // Escape the specified directory in case it contains characters that have
    // special meaning in glob patterns (e.g., `[` or `]`).
    let directory = Pattern::escape(directory.to_str().unwrap());
    let directory = Path::new(&directory);

    // Join the escaped directory to the filename glob patterns to obtain
    // complete glob patterns for the files being searched for.
    let paths = filenames
        .iter()
        .map(|f| directory.join(f).to_str().unwrap().to_owned());

    // Prevent wildcards from matching path separators to ensure that the search
    // is limited to the specified directory.
    let mut options = MatchOptions::new();
    options.require_literal_separator = true;

    let mut results = paths
        .map(|p| glob::glob_with(&p, options))
        .filter_map(Result::ok)
        .flatten()
        .filter_map(|p| {
            let path = p.ok()?;
            let filename = path.file_name()?.to_str().unwrap();
            Some((directory.to_owned(), filename.into()))
        })
        .collect::<Vec<_>>();

    if target_os!("windows") && directory.ends_with("lib") {
        let sibling = directory.parent().unwrap().join("bin");
        results.extend(search_directory(&sibling, filenames));
    }

    results
}

pub fn search_files(filenames: &[String], variable: &str) -> Vec<(PathBuf, String)> {
    if let Ok(path) = env::var(variable).map(|d| Path::new(&d).to_path_buf()) {
        // Check if the path is a matching file.
        if let Some(parent) = path.parent() {
            let filename = path.file_name().unwrap().to_str().unwrap();
            let libraries = search_directory(parent, filenames);
            if libraries.iter().any(|(_, f)| f == filename) {
                return vec![(parent.into(), filename.into())];
            }
        }

        // Check if the path is directory containing a matching file.
        return search_directory(&path, filenames);
    }

    let mut directories: Vec<String> = vec![];

    // Search the directories in the `LD_LIBRARY_PATH` environment variable.
    if let Ok(path) = env::var("LD_LIBRARY_PATH") {
        directories.extend(
            env::split_paths(&path).map(|x| x.to_string_lossy().into()),
        );
    }

    if target_os!("linux") || target_os!("freebsd") {
        directories.extend(DIRECTORIES_LINUX.iter().map(|x| x.to_string()));
    } else if target_os!("macos") {
        directories.extend(DIRECTORIES_MACOS.iter().map(|x| x.to_string()));
    } else if target_os!("windows") {
        let msvc = target_env!("msvc");
        directories.extend(
            DIRECTORIES_WINDOWS
                .iter()
                .filter(|d| d.1 || !msvc)
                .map(|d| d.0.into()),
        );
    }

    if let Ok(home_dir) = env::var("HOME") {
        let local_dir: PathBuf = [home_dir, ".local".into()].iter().collect();
        directories.extend(
            DIRECTORIES_LOCAL
                .iter()
                .map(|x| local_dir.join(*x).to_string_lossy().into()),
        );
    }

    // We use temporary directories when testing the build script, so we'll
    // remove the prefixes that make the directories absolute.
    let directories = if test!() {
        directories
            .iter()
            .map(|d| {
                d.strip_prefix('/')
                    .or_else(|| d.strip_prefix("C:\\"))
                    .unwrap_or(d)
                    .into()
            })
            .collect::<Vec<_>>()
    } else {
        directories
    };

    let mut options = MatchOptions::new();
    options.case_sensitive = false;
    options.require_literal_separator = true;

    let directories = directories
        .iter()
        .flat_map(|x| {
            glob::glob_with(x, options)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|p| p.is_dir())
                .collect::<Vec<PathBuf>>()
        })
        .unique()
        .collect::<Vec<PathBuf>>();

    directories
        .iter()
        .flat_map(|p| search_directory(Path::new(p), filenames))
        .unique()
        .collect()
}

/// Extracts the version components in a shared library filename.
fn parse_version(filename: &str) -> Vec<u32> {
    let ss = filename.split('.');
    ss.skip(1).filter_map(|s| s.parse().ok()).collect_vec()
}

pub fn search_libs(
    libs: &[&str],
    // runtime: bool,
    variable: &str,
) -> Result<(PathBuf, String, Vec<u32>), String> {
    let files = libs
        .iter()
        .flat_map(|x| {
            [
                format!(
                    "{}{}.{}",
                    env::consts::DLL_PREFIX,
                    x,
                    env::consts::DLL_EXTENSION
                ),
                format!(
                    "{}{}.{}.*",
                    env::consts::DLL_PREFIX,
                    x,
                    env::consts::DLL_EXTENSION
                ),
                format!(
                    "{}{}.*.{}",
                    env::consts::DLL_PREFIX,
                    x,
                    env::consts::DLL_EXTENSION
                ),
            ]
        })
        .collect::<Vec<String>>();

    let mut valid: Vec<_> = vec![];
    for (directory, filename) in search_files(&files, variable) {
        let ver = parse_version(filename.as_str());
        valid.push((directory, filename, ver))
    }

    println!("cargo:warning={:?}", &valid);

    if !valid.is_empty() {
        valid
            .iter()
            .max_by_key(|x| &x.1)
            .cloned()
            .ok_or("unreachable".into())
    } else {
        Err(format!(
            "couldn't find any valid shared libraries matching: [{}], set the \
         `{}` environment variable to a path where one of these files",
            files
                .iter()
                .map(|f| format!("'{}'", f))
                .collect::<Vec<_>>()
                .join(", "),
            variable,
        ))
    }
}
