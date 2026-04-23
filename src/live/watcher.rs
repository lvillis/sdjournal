use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fd::OwnedFd;
use rustix::fs::inotify;
use rustix::io::Errno;
use std::mem::MaybeUninit;

pub(super) struct InotifyWatcher {
    inotify: OwnedFd,
    buffer: Vec<MaybeUninit<u8>>,
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
            | inotify::WatchFlags::ATTRIB
            | inotify::WatchFlags::CREATE
            | inotify::WatchFlags::DELETE
            | inotify::WatchFlags::MOVED_FROM
            | inotify::WatchFlags::MOVED_TO
            | inotify::WatchFlags::MOVE_SELF
            | inotify::WatchFlags::DELETE_SELF;

        let mut added = 0usize;
        for path in watch_paths {
            if inotify::add_watch(&inotify, path.as_os_str().as_bytes(), mask).is_ok() {
                added = added.saturating_add(1);
            }
        }
        if added == 0 {
            return None;
        }

        Some(Self {
            inotify,
            buffer: vec![MaybeUninit::uninit(); 4096],
        })
    }

    pub(super) fn wait(&mut self, timeout: Duration) -> bool {
        let timeout = timeout.min(Duration::from_millis(i32::MAX as u64));
        let timeout = Timespec::try_from(timeout).ok();
        let mut pfd = [PollFd::new(&self.inotify, PollFlags::IN)];

        loop {
            pfd[0].clear_revents();
            match poll(&mut pfd, timeout.as_ref()) {
                Ok(ready) if ready > 0 => {
                    return self.drain_ready_events();
                }
                Ok(_) => return false,
                Err(Errno::INTR) => continue,
                Err(_) => return false,
            }
        }
    }

    fn drain_ready_events(&mut self) -> bool {
        let mut reader = inotify::Reader::new(&self.inotify, &mut self.buffer);
        let mut saw_event = false;

        loop {
            match reader.next() {
                Ok(_) => saw_event = true,
                Err(Errno::AGAIN) => return saw_event,
                Err(Errno::INTR) => continue,
                Err(_) => return false,
            }
        }
    }
}
