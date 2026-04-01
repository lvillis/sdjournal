use std::path::PathBuf;
use std::time::Duration;

pub(super) struct InotifyWatcher {
    inotify: inotify::Inotify,
    buffer: Vec<u8>,
}

impl InotifyWatcher {
    pub(super) fn new(watch_paths: &[PathBuf]) -> Option<Self> {
        use inotify::WatchMask;

        let inotify = match inotify::Inotify::init() {
            Ok(v) => v,
            Err(_) => return None,
        };

        let mask = WatchMask::MODIFY
            | WatchMask::CLOSE_WRITE
            | WatchMask::ATTRIB
            | WatchMask::CREATE
            | WatchMask::DELETE
            | WatchMask::MOVED_FROM
            | WatchMask::MOVED_TO
            | WatchMask::MOVE_SELF
            | WatchMask::DELETE_SELF;

        let mut added = 0usize;
        for p in watch_paths {
            if inotify.watches().add(p, mask).is_ok() {
                added = added.saturating_add(1);
            }
        }
        if added == 0 {
            return None;
        }

        Some(Self {
            inotify,
            buffer: vec![0u8; 4096],
        })
    }

    pub(super) fn wait(&mut self, timeout: Duration) -> bool {
        use std::os::unix::io::AsRawFd as _;

        let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let fd = self.inotify.as_raw_fd();
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };

        loop {
            // SAFETY: `pfd` points to initialized stack memory, `fd` comes from the live
            // `inotify` handle owned by `self`, and the kernel writes at most one `pollfd`.
            let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if r > 0 {
                let _ = self.inotify.read_events(&mut self.buffer);
                return true;
            }
            if r == 0 {
                return false;
            }

            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
    }
}
