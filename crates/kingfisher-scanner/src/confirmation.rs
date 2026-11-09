//! Opaque confirmation iterator used by the scanner and explicitly unstable CLI API.

/// Confirmation matches for a candidate window. `search` yields every match;
/// endpoint-indexed construction yields only matches ending at the window end.
/// Callers must still verify the capture's candidate endpoint before accepting it.
pub struct IndexedCaptures<'r, 'h> {
    state: State<'r, 'h>,
}

impl<'r, 'h> IndexedCaptures<'r, 'h> {
    pub fn search(regex: &'r regex::bytes::Regex, haystack: &'h [u8]) -> Self {
        Self { state: State::Search(regex.captures_iter(haystack)) }
    }

    /// Replay the complete input, retaining the original regex's capture semantics.
    pub fn replay(
        regex: &'r regex::bytes::Regex,
        haystack: &'h [u8],
        replay: Option<&'r kingfisher_rules::replay_regex::ReplayRegex>,
    ) -> Self {
        match replay {
            Some(replay) => Self { state: State::Replay(replay.captures_iter(haystack)) },
            None => Self::search(regex, haystack),
        }
    }

    pub(crate) fn one(captures: Option<regex::bytes::Captures<'h>>) -> Self {
        Self { state: State::One(captures) }
    }

    pub(crate) fn from_position(
        regex: &'r regex::bytes::Regex,
        haystack: &'h [u8],
        position: usize,
    ) -> Self {
        Self { state: State::SearchFrom { regex, haystack, position } }
    }

    pub(crate) fn into_legacy(self) -> crate::primitives::ConfirmationCaptures<'r, 'h> {
        use crate::primitives::ConfirmationCaptures;
        match self.state {
            State::One(captures) => ConfirmationCaptures::One(captures),
            State::Search(captures) => ConfirmationCaptures::Search(captures),
            State::Replay(captures) => ConfirmationCaptures::Search(captures.into_legacy()),
            state @ State::SearchFrom { .. } => ConfirmationCaptures::One(Self { state }.next()),
        }
    }

    #[cfg(test)]
    pub(crate) fn search_position(&self) -> Option<usize> {
        match self.state {
            State::SearchFrom { position, .. } => Some(position),
            _ => None,
        }
    }
}

enum State<'r, 'h> {
    One(Option<regex::bytes::Captures<'h>>),
    Search(regex::bytes::CaptureMatches<'r, 'h>),
    Replay(kingfisher_rules::replay_regex::ReplayCaptures<'r, 'h>),
    SearchFrom { regex: &'r regex::bytes::Regex, haystack: &'h [u8], position: usize },
}

impl<'h> IndexedCaptures<'_, 'h> {
    pub(crate) fn next_with_control(
        &mut self,
        control: &crate::ScanControl,
    ) -> Result<Option<regex::bytes::Captures<'h>>, crate::ScanAborted> {
        control.check()?;
        Ok(match &mut self.state {
            State::One(captures) => captures.take(),
            State::Search(captures) => captures.next(),
            State::Replay(captures) => captures.next(),
            State::SearchFrom { regex, haystack, position } => {
                while *position <= haystack.len() {
                    control.check()?;
                    let Some(captures) = regex.captures_at(haystack, *position) else {
                        return Ok(None);
                    };
                    let full = captures.get(0).unwrap();
                    if full.end() == haystack.len() {
                        *position = haystack.len().saturating_add(1);
                        return Ok(Some(captures));
                    }
                    // Indexed construction normally certifies a consuming regex.
                    // Remain terminating even if an empty-capable regex reaches here.
                    *position = full.end().saturating_add(usize::from(full.is_empty()));
                }
                None
            }
        })
    }
}

impl<'h> Iterator for IndexedCaptures<'_, 'h> {
    type Item = regex::bytes::Captures<'h>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_with_control(&crate::ScanControl::default())
            .expect("unlimited scan cannot be cancelled")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_capable_endpoint_search_terminates() {
        let regex = regex::bytes::Regex::new("a*").unwrap();
        let mut captures = IndexedCaptures::from_position(&regex, b"bbb", 0);
        let found = captures.next().unwrap();
        assert_eq!(found.get(0).unwrap().range(), 3..3);
        assert!(captures.next().is_none());
    }

    #[test]
    fn replay_keeps_cancellation_and_resumed_legacy_captures() {
        let regex = regex::bytes::RegexBuilder::new("(?P<token>[ab])")
            .unicode(false)
            .size_limit(16 * 1024 * 1024)
            .build()
            .unwrap();
        let replay = kingfisher_rules::replay_regex::ReplayRegex::new(&regex).unwrap();
        for finder in [None, Some(&replay)] {
            let token = crate::CancellationToken::default();
            let control = crate::ScanControl::default().with_cancellation(token.clone());
            let mut captures = IndexedCaptures::replay(&regex, b"a b a", finder);
            assert_eq!(
                captures.next_with_control(&control).unwrap().unwrap().get(0).unwrap().range(),
                0..1
            );
            token.cancel();
            assert!(matches!(
                captures.next_with_control(&control),
                Err(crate::ScanAborted::Cancelled)
            ));
            let remaining: Vec<_> = captures
                .into_legacy()
                .map(|capture| capture.name("token").unwrap().range())
                .collect();
            assert_eq!(remaining, [2..3, 4..5]);
        }
    }

    #[test]
    fn legacy_confirmation_keeps_the_resumed_endpoint_search() {
        let regex = regex::bytes::Regex::new("token").unwrap();
        let found: Vec<_> = IndexedCaptures::from_position(&regex, b"token token", 6)
            .into_legacy()
            .map(|captures| captures.get(0).unwrap().range())
            .collect();
        assert_eq!(found, vec![6..11]);
    }
}
