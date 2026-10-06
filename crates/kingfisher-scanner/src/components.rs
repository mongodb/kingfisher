//! Propagate required-component failures without rescanning unaffected findings.
use std::collections::VecDeque;

use crate::{ScanAborted, ScanControl};

/// Watch one live supporting finding per required dependency. Only losing that
/// witness requires another lookup; cycles with live support remain intact.
pub fn dependency_keep<T>(
    dependency_counts: &[usize],
    index: &mut T,
    mut find_candidate: impl FnMut(&T, usize, usize) -> Result<Option<usize>, ScanAborted>,
    mut remove: impl FnMut(&mut T, usize),
    control: &ScanControl,
) -> Result<Vec<bool>, ScanAborted> {
    let mut keep = vec![true; dependency_counts.len()];
    let mut watchers = vec![Vec::new(); keep.len()];
    let mut removed = VecDeque::new();
    for (primary, &count) in dependency_counts.iter().enumerate() {
        control.check()?;
        for dependency in 0..count {
            control.check()?;
            if let Some(candidate) = find_candidate(index, primary, dependency)? {
                watchers[candidate].push((primary, dependency));
            } else {
                keep[primary] = false;
                remove(index, primary);
                removed.push_back(primary);
                break;
            }
        }
    }
    while let Some(candidate) = removed.pop_front() {
        control.check()?;
        for (primary, dependency) in std::mem::take(&mut watchers[candidate]) {
            control.check()?;
            if !keep[primary] {
                continue;
            }
            if let Some(replacement) = find_candidate(index, primary, dependency)? {
                watchers[replacement].push((primary, dependency));
            } else {
                keep[primary] = false;
                remove(index, primary);
                removed.push_back(primary);
            }
        }
    }
    Ok(keep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keep_graph(graph: &[Vec<Vec<usize>>]) -> (Vec<bool>, usize) {
        let mut lookups = 0;
        let counts: Vec<_> = graph.iter().map(Vec::len).collect();
        let keep = dependency_keep(
            &counts,
            &mut vec![true; graph.len()],
            |active, primary, dependency| {
                lookups += 1;
                Ok(graph[primary][dependency].iter().copied().find(|&i| active[i]))
            },
            |active, removed| active[removed] = false,
            &ScanControl::default(),
        )
        .unwrap();
        (keep, lookups)
    }

    #[test]
    fn long_reverse_cascade_checks_only_affected_dependencies() {
        let count = 10_000;
        let graph: Vec<_> =
            (0..count).map(|i| vec![if i + 1 < count { vec![i + 1] } else { vec![] }]).collect();
        let (keep, lookups) = keep_graph(&graph);
        assert!(keep.iter().all(|&live| !live));
        assert_eq!(lookups, count * 2 - 1);
    }

    #[test]
    fn replacement_witnesses_and_live_cycles_survive() {
        let graph = vec![
            vec![vec![1, 2]],
            vec![vec![]],
            vec![vec![3]],
            vec![vec![2]],
            vec![vec![2], vec![1]],
        ];
        assert_eq!(keep_graph(&graph).0, vec![true, false, true, true, false]);
    }

    #[test]
    fn worklist_agrees_with_fixed_point_oracle() {
        let mut seed = 537_u64;
        for _ in 0..500 {
            let mut next = || {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 32) as usize
            };
            let graph: Vec<Vec<Vec<usize>>> = (0..32)
                .map(|_| {
                    (0..next() % 3)
                        .map(|_| (0..next() % 4).map(|_| next() % 32).collect())
                        .collect()
                })
                .collect();
            let mut expected = vec![true; graph.len()];
            loop {
                let mut changed = false;
                for (primary, dependencies) in graph.iter().enumerate() {
                    if expected[primary]
                        && dependencies.iter().any(|candidates| {
                            !candidates.iter().any(|&candidate| expected[candidate])
                        })
                    {
                        expected[primary] = false;
                        changed = true;
                    }
                }
                if !changed {
                    break;
                }
            }
            assert_eq!(keep_graph(&graph).0, expected);
        }
    }

    #[test]
    fn interrupted_propagation_returns_an_error() {
        let token = crate::CancellationToken::default();
        let control = ScanControl::default().with_cancellation(token.clone());
        let result = dependency_keep(
            &[1, 1],
            &mut (),
            |_, primary, _| Ok((primary == 0).then_some(1)),
            |_, _| token.cancel(),
            &control,
        );
        assert_eq!(result.unwrap_err(), ScanAborted::Cancelled);
    }
}
