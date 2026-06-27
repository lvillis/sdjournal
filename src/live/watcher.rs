use std::collections::HashMap;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fd::OwnedFd;
use rustix::fs::inotify;
use rustix::io::Errno;

use super::WatchChange;

#[derive(Clone)]
enum WatchKind {
    Directory,
    File,
}

#[derive(Clone)]
struct WatchTarget {
    path: PathBuf,
    kind: WatchKind,
}

pub(super) struct InotifyWatcher {
    inotify: OwnedFd,
    buffer: Vec<MaybeUninit<u8>>,
    targets: HashMap<i32, WatchTarget>,
}

impl InotifyWatcher {
    pub(super) fn new(watch_paths: &[PathBuf]) -> Option<Self> {
        let inotify =
            match inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK) {
                Ok(inotify) => inotify,
                Err(_) => return None,
            };

        let mask = inotify::WatchFlags::MODIFY
            | inotify::WatchFlags::CLOSE_WRITE
            | inotify::WatchFlags::CREATE
            | inotify::WatchFlags::DELETE
            | inotify::WatchFlags::MOVED_FROM
            | inotify::WatchFlags::MOVED_TO
            | inotify::WatchFlags::MOVE_SELF
            | inotify::WatchFlags::DELETE_SELF;

        let mut targets = HashMap::new();
        for path in watch_paths {
            let Some(kind) = watch_kind(path) else {
                continue;
            };
            let Ok(wd) = inotify::add_watch(&inotify, path.as_os_str().as_bytes(), mask) else {
                continue;
            };
            targets.insert(
                wd,
                WatchTarget {
                    path: path.clone(),
                    kind,
                },
            );
        }

        if targets.is_empty() {
            return None;
        }

        let watcher = Self {
            inotify,
            buffer: vec![MaybeUninit::uninit(); 4096],
            targets,
        };
        Some(watcher)
    }

    pub(super) fn wait(&mut self, timeout: Duration) -> WatchChange {
        let timeout = timeout.min(Duration::from_millis(i32::MAX as u64));
        let timeout = Timespec::try_from(timeout).ok();
        let mut pfd = [PollFd::new(&self.inotify, PollFlags::IN)];

        loop {
            pfd[0].clear_revents();
            match poll(&mut pfd, timeout.as_ref()) {
                Ok(ready) if ready > 0 => return self.drain_ready_events(),
                Ok(_) => {
                    return WatchChange {
                        topology_changed: false,
                        modified_paths: Vec::new(),
                    };
                }
                Err(Errno::INTR) => continue,
                Err(_) => {
                    return WatchChange {
                        topology_changed: true,
                        modified_paths: Vec::new(),
                    };
                }
            }
        }
    }

    fn drain_ready_events(&mut self) -> WatchChange {
        let targets = &self.targets;
        let mut reader = inotify::Reader::new(&self.inotify, &mut self.buffer);
        let mut change = WatchChange {
            topology_changed: false,
            modified_paths: Vec::new(),
        };

        loop {
            match reader.next() {
                Ok(event) => apply_event(targets, &event, &mut change),
                Err(Errno::AGAIN) => {
                    change.modified_paths.sort();
                    change.modified_paths.dedup();
                    return change;
                }
                Err(Errno::INTR) => continue,
                Err(_) => {
                    change.topology_changed = true;
                    return change;
                }
            }
        }
    }
}

fn watch_kind(path: &std::path::Path) -> Option<WatchKind> {
    let ft = std::fs::metadata(path).ok()?.file_type();
    if ft.is_dir() {
        Some(WatchKind::Directory)
    } else if ft.is_file() {
        Some(WatchKind::File)
    } else {
        None
    }
}

fn join_cstr_path(base: &std::path::Path, name: &std::ffi::CStr) -> Option<PathBuf> {
    let bytes = name.to_bytes();
    if bytes.is_empty() {
        return None;
    }
    Some(base.join(OsStr::from_bytes(bytes)))
}

fn apply_event(
    targets: &HashMap<i32, WatchTarget>,
    event: &inotify::Event<'_>,
    change: &mut WatchChange,
) {
    let Some(target) = targets.get(&event.wd()) else {
        change.topology_changed = true;
        return;
    };

    let flags = event.events();
    let topology_flags = inotify::ReadFlags::CREATE
        | inotify::ReadFlags::DELETE
        | inotify::ReadFlags::MOVED_FROM
        | inotify::ReadFlags::MOVED_TO
        | inotify::ReadFlags::MOVE_SELF
        | inotify::ReadFlags::DELETE_SELF;

    if flags.intersects(topology_flags) {
        change.topology_changed = true;
    }

    let modified_flags = inotify::ReadFlags::MODIFY | inotify::ReadFlags::CLOSE_WRITE;

    if !flags.intersects(modified_flags) {
        return;
    }

    match target.kind {
        WatchKind::File => change.modified_paths.push(target.path.clone()),
        WatchKind::Directory => {
            if let Some(name) = event.file_name()
                && let Some(path) = join_cstr_path(&target.path, name)
            {
                change.modified_paths.push(path);
            }
        }
    }
}
