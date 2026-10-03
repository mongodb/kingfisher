//! Contain Git and its helpers before any of their code runs.

use std::{
    io,
    mem::{size_of, zeroed},
    os::windows::{
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::CommandExt,
    },
    process::{Child, Command},
};

use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        },
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        },
        Threading::{CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
    },
};

// Closing the last handle terminates every process in the job, including helpers
// holding stdout/stderr open. OwnedHandle also closes it on error/unwind paths.
pub(super) struct Job(OwnedHandle);

impl Job {
    fn new() -> io::Result<Self> {
        // SAFETY: null security attributes/name create an unnamed, non-inheritable job.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateJobObjectW returned a valid handle owned by this function.
        let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });
        // SAFETY: zero is valid for all fields; only LimitFlags is needed here.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the handle is live and the buffer has the specified layout/size.
        if unsafe {
            SetInformationJobObject(
                job.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn assign_and_resume(&self, child: &Child) -> io::Result<()> {
        // SAFETY: both handles are live. The child was spawned suspended so it
        // cannot launch a helper before inheriting our job membership.
        if unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), child.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }

        // Stable Rust exposes Child's process handle, but not its primary thread
        // handle. A suspended, newly created child has only that one thread.
        // SAFETY: these flags request a snapshot of threads; no pointers are passed.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the snapshot is a valid owned handle.
        let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
        // SAFETY: zero is valid; dwSize tells the API the buffer's layout.
        let mut entry: THREADENTRY32 = unsafe { zeroed() };
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        // SAFETY: snapshot is live and entry is a correctly sized writable buffer.
        let mut found = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
        while found != 0 {
            if entry.th32OwnerProcessID == child.id() {
                // SAFETY: the thread ID came from the snapshot; request only resume access.
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if thread.is_null() {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: OpenThread returned a valid owned handle.
                let thread = unsafe { OwnedHandle::from_raw_handle(thread) };
                // SAFETY: the thread is the suspended child's live primary thread.
                if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
                    return Err(io::Error::last_os_error());
                }
                return Ok(());
            }
            // SAFETY: snapshot is live and entry remains a writable buffer.
            found = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "Git child thread was not found"))
    }
}

pub(super) fn spawn(cmd: &mut Command, bounded: bool) -> io::Result<(Child, Option<Job>)> {
    if !bounded {
        return cmd.spawn().map(|child| (child, None));
    }
    let job = Job::new()?;
    cmd.creation_flags(CREATE_SUSPENDED);
    let mut child = cmd.spawn()?;
    if let Err(error) = job.assign_and_resume(&child) {
        // Also kill explicitly if assignment failed before the job owned the child.
        drop(job);
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok((child, Some(job)))
}
