//! Bounded finding channels and batched datastore writes.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::time::{Duration, Instant};
use tracing::{debug, error_span};

use crate::findings_store::{self, FindingsStore};

pub(super) fn create_datastore_channel(
    num_jobs: usize,
) -> (
    crossbeam_channel::Sender<findings_store::FindingsStoreMessage>,
    crossbeam_channel::Receiver<findings_store::FindingsStoreMessage>,
) {
    const BATCH_SIZE: usize = 1024;
    let channel_size = std::cmp::max(num_jobs * BATCH_SIZE, 16 * BATCH_SIZE);
    crossbeam_channel::bounded(channel_size)
}

pub(super) fn spawn_datastore_writer_thread(
    datastore: Arc<Mutex<FindingsStore>>,
    recv_ds: crossbeam_channel::Receiver<findings_store::FindingsStoreMessage>,
    dedup: bool,
) -> Result<std::thread::JoinHandle<Result<(usize, usize)>>> {
    std::thread::Builder::new()
        .name("in-memory-storage".to_string())
        .spawn(move || -> Result<_> {
            let _span = error_span!("in-memory-storage").entered();
            let mut total_recording_time = Duration::default();
            let mut num_matches_added = 0;
            let mut total_messages = 0;
            // Batch writes to reduce datastore lock contention; flush partial batches periodically.
            const BATCH_SIZE: usize = 32 * 1024;
            const COMMIT_INTERVAL: Duration = Duration::from_secs(2);
            let mut batch = Vec::with_capacity(BATCH_SIZE);
            let mut last_commit_time = Instant::now();
            'outer: loop {
                while batch.len() < BATCH_SIZE {
                    match recv_ds.try_recv() {
                        Ok(message) => {
                            total_messages += 1;
                            batch.push(message);
                        }
                        Err(crossbeam_channel::TryRecvError::Empty) => {
                            if !batch.is_empty()
                                && (batch.len() >= BATCH_SIZE
                                    || last_commit_time.elapsed() >= COMMIT_INTERVAL)
                            {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(crossbeam_channel::TryRecvError::Disconnected) => {
                            break 'outer;
                        }
                    }
                }
                if !batch.is_empty() {
                    let t1 = Instant::now();
                    let commit_batch =
                        std::mem::replace(&mut batch, Vec::with_capacity(BATCH_SIZE));
                    let num_added = datastore.lock().unwrap().record(commit_batch, dedup);
                    last_commit_time = Instant::now();
                    num_matches_added += num_added;
                    total_recording_time += t1.elapsed();
                }
            }
            // Disconnection exits the fill loop before flushing its final partial batch.
            if !batch.is_empty() {
                let t1 = Instant::now();
                let num_added = datastore.lock().unwrap().record(batch, dedup);

                num_matches_added += num_added;
                total_recording_time += t1.elapsed();
            }
            let num_matches = datastore.lock().unwrap().get_num_matches();
            debug!(
                "Summary: recorded {num_matches} matches from {total_messages} messages in {:.6}s",
                total_recording_time.as_secs_f64(),
            );
            Ok((num_matches, num_matches_added))
        })
        .context("Failed to spawn datastore writer thread")
}
