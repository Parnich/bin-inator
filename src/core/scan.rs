use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
};

/// Expand files and directories into a sorted list of regular files.
///
/// With `recursive == false`, only the top level of a directory is read.
/// Symlinked directories are followed once; cycles are skipped.
pub fn collect_files(root: &Path, recursive: bool) -> io::Result<Vec<PathBuf>> {
    collect_files_excluding(root, recursive, None)
}

/// Like [`collect_files`], but skips a directory subtree such as the output
/// directory so a second run does not convert its own results.
pub fn collect_files_excluding(
    root: &Path,
    recursive: bool,
    exclude: Option<&Path>,
) -> io::Result<Vec<PathBuf>> {
    let exclude = exclude.and_then(|path| fs::canonicalize(path).ok());
    let mut files = Vec::new();
    let mut visited = HashSet::new();
    collect_into(
        root,
        recursive,
        exclude.as_deref(),
        &mut visited,
        &mut files,
    )?;
    files.sort();
    files.dedup();
    Ok(files)
}

fn collect_into(
    path: &Path,
    recursive: bool,
    exclude: Option<&Path>,
    visited: &mut HashSet<PathBuf>,
    files: &mut Vec<PathBuf>,
) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        if !is_excluded(path, exclude) {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }

    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if exclude.is_some_and(|exclude| canonical.starts_with(exclude)) {
        return Ok(());
    }
    if !visited.insert(canonical) {
        return Ok(());
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let child_metadata = fs::metadata(&child)?;
        if child_metadata.is_dir() {
            if recursive {
                collect_into(&child, recursive, exclude, visited, files)?;
            }
        } else if child_metadata.is_file() && !is_excluded(&child, exclude) {
            files.push(child);
        }
    }

    Ok(())
}

fn is_excluded(path: &Path, exclude: Option<&Path>) -> bool {
    let Some(exclude) = exclude else {
        return false;
    };
    fs::canonicalize(path)
        .map(|path| path.starts_with(exclude))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_top_level_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.dat"), b"a").unwrap();
        fs::create_dir_all(dir.path().join("nested")).unwrap();
        fs::write(dir.path().join("nested/b.dat"), b"b").unwrap();

        let files = collect_files(dir.path(), false).unwrap();
        assert_eq!(files, vec![dir.path().join("a.dat")]);

        let files = collect_files(dir.path(), true).unwrap();
        assert_eq!(
            files,
            vec![dir.path().join("a.dat"), dir.path().join("nested/b.dat")]
        );
    }

    #[test]
    fn passes_files_through() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("single.bin");
        fs::write(&file, b"x").unwrap();
        assert_eq!(collect_files(&file, false).unwrap(), vec![file.clone()]);
    }

    #[test]
    fn skips_excluded_output_directory() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.dat"), b"a").unwrap();
        let output = dir.path().join("out");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("a.bin"), b"old").unwrap();

        let files = collect_files_excluding(dir.path(), true, Some(&output)).unwrap();
        assert_eq!(files, vec![dir.path().join("a.dat")]);
    }
}
