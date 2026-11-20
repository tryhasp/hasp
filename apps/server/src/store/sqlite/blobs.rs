use std::fs;
use std::path::{Path, PathBuf};

use hasp_crypto::{sha256, to_hex};
use hasp_proto::AttId;

use crate::persist::{create_dir_durable, sync_dir, write_durable};

#[derive(Debug)]
pub(super) enum Undo {
    Created(PathBuf),
    Replaced(PathBuf, Vec<u8>),
}

#[derive(Debug)]
pub(super) struct Blobs {
    root: PathBuf,
}

impl Blobs {
    pub(super) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn path(&self, att: &AttId, idx: u64) -> PathBuf {
        let name = to_hex(att.as_bytes());
        let (first, rest) = name.split_at(2);
        let second = rest.get(..2).unwrap_or_default();
        self.root
            .join(first)
            .join(second)
            .join(&name)
            .join(idx.to_string())
    }

    pub(super) fn write(&self, att: &AttId, idx: u64, bytes: &[u8]) -> std::io::Result<Undo> {
        let path = self.path(att, idx);
        let undo = match fs::read(&path) {
            Ok(old) => Undo::Replaced(path.clone(), old),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Undo::Created(path.clone())
            }
            Err(error) => return Err(error),
        };
        write_durable(&path, bytes)?;
        Ok(undo)
    }

    pub(super) fn read(&self, att: &AttId, idx: u64) -> std::io::Result<Vec<u8>> {
        fs::read(self.path(att, idx))
    }

    pub(super) fn undo(undo: Undo) -> std::io::Result<()> {
        match undo {
            Undo::Created(path) => match fs::remove_file(&path) {
                Ok(()) => path.parent().map_or(Ok(()), sync_dir),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            },
            Undo::Replaced(path, old) => write_durable(&path, &old),
        }
    }

    pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
        sha256(&[bytes])
    }

    pub(super) fn prune_empty_dirs(&self) -> std::io::Result<()> {
        if !self.root.exists() {
            return Ok(());
        }
        for first in dirs(&self.root)? {
            for second in dirs(&first)? {
                for att_dir in dirs(&second)? {
                    fs::remove_dir(&att_dir).ok();
                }
                fs::remove_dir(&second).ok();
            }
            fs::remove_dir(&first).ok();
        }
        Ok(())
    }

    pub(super) fn ensure_root(&self) -> std::io::Result<()> {
        create_dir_durable(&self.root)
    }

    pub(super) fn files(&self) -> std::io::Result<Vec<(AttId, Option<u64>, PathBuf)>> {
        let mut out = Vec::new();
        if !self.root.exists() {
            return Ok(out);
        }
        for first in dirs(&self.root)? {
            for second in dirs(&first)? {
                for att_dir in dirs(&second)? {
                    let Some(att) = att_dir
                        .file_name()
                        .and_then(|n| n.to_str())
                        .and_then(parse_att)
                    else {
                        continue;
                    };
                    for entry in fs::read_dir(&att_dir)? {
                        let path = entry?.path();
                        let idx = path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .and_then(|n| n.parse::<u64>().ok());
                        out.push((att, idx, path));
                    }
                }
            }
        }
        Ok(out)
    }
}

fn dirs(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            out.push(entry.path());
        }
    }
    Ok(out)
}

fn parse_att(name: &str) -> Option<AttId> {
    let bytes = hasp_crypto::from_hex(name)?;
    let array: [u8; 16] = bytes.as_slice().try_into().ok()?;
    Some(AttId::from_bytes(array))
}
