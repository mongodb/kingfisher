use anyhow::Result;
use tokio::time::Instant;
use tracing::{debug_span, trace};

use crate::{
    blob::{Blob, BlobMetadata},
    guesser::{Guesser, Input},
    location::LocationMapping,
    matcher::{Match, Matcher, OwnedBlobMatch, ScanResult},
    origin::{Origin, OriginSet},
    scanner::repos::DatastoreMessage,
    Path,
};

/// A combined matcher, content type guesser, and a number of parameters that
/// don't change within one `scan` run
pub struct BlobProcessor<'a> {
    pub matcher: Matcher<'a>,
    pub guesser: Guesser,
}

impl<'a> BlobProcessor<'a> {
    pub fn run(
        &mut self,
        origin: OriginSet,
        blob: Blob,
        no_dedup: bool,
    ) -> Result<Option<DatastoreMessage>> {
        let blob_id = blob.id.hex();
        let _span = debug_span!("matcher", blob_id).entered();
        let t1 = Instant::now();
        let res = self.matcher.scan_blob(&blob, &origin, None, false, no_dedup)?;
        let scan_us = t1.elapsed().as_micros();
        match res {
            // blob already seen, but with no matches; nothing to do!
            ScanResult::SeenSansMatches => {
                trace!("({scan_us}us) blob already scanned with no matches");
                Ok(None)
            }

            // blob already seen; all we need to do is record its origin
            ScanResult::SeenWithMatches => {
                trace!("({scan_us}us) blob already scanned with matches");
                let metadata = BlobMetadata {
                    id: blob.id,
                    num_bytes: blob.len(),
                    mime_essence: None,
                    charset: None,
                    language: None,
                };
                Ok(Some((origin, metadata, Vec::new())))
            }

            // blob has not been seen; need to record blob metadata, origin, and matches
            ScanResult::New(matches) => {
                trace!("({scan_us}us) blob newly scanned; {} matches", matches.len());
                // If there are no matches, we can bail out here and avoid recording anything.
                // UNLESS the `--blob-metadata=all` mode was specified; then we need to record
                // the origin for _all_ seen blobs.
                if matches.is_empty() {
                    return Ok(None);
                }
                let md = MetadataResult::from_blob_and_origin(&self.guesser, &blob, &origin);
                let metadata = BlobMetadata {
                    id: blob.id,
                    num_bytes: blob.len(),
                    mime_essence: md.mime_essence,
                    charset: md.charset,
                    language: md.language,
                };

                let mut origin_type = "unknown";
                for origin_entry in origin.iter() {
                    let type_str = match origin_entry {
                        Origin::GitRepo(_) => "git",
                        Origin::File(_) => "file",
                        Origin::Extended(_) => "ext",
                    };
                    // println!("Origin type: {}", type_str);
                    if origin_type == "unknown" {
                        origin_type = type_str;
                        break; // Exit loop after first match
                    }
                }

                let loc_mapping = LocationMapping::new(&blob.bytes());
                let converted_matches: Vec<(Option<f64>, Match)> = matches
                    .into_iter()
                    .map(|m| {
                        let converted_match = Match::convert_owned_blobmatch_to_match(
                            &loc_mapping,
                            &OwnedBlobMatch::from_blob_match(m),
                            origin_type,
                        );
                        (None, converted_match)
                    })
                    .collect();
                Ok(Some((origin, metadata, converted_matches)))
            }
        }
    }
}

#[derive(Default)]
struct MetadataResult {
    mime_essence: Option<String>,
    language: Option<String>,
    charset: Option<String>,
}
impl MetadataResult {
    fn from_blob_and_origin(guesser: &Guesser, blob: &Blob, origin: &OriginSet) -> MetadataResult {
        let blob_path: Option<&'_ Path> = origin.iter().find_map(|p| p.blob_path());
        let input = match blob_path {
            None => Input::from_bytes(&blob.bytes()), // Use Input directly
            Some(blob_path) => {
                Input::from_path_and_bytes(blob_path, &blob.bytes()) // Use Input
                                                                     // directly
            }
        };
        let guess = guesser.guess(input);
        let mime_essence = guess.path_guess().map(|s| s.to_string());
        let language = guess.content_guess().map(ToOwned::to_owned);
        let charset = guess.path_guess().and_then(|_| guess.get_param("charset")); // Call get_param on Guess directly
        MetadataResult { mime_essence, language, charset }
    }
}
