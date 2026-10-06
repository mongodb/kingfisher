use anyhow::Result;
use tl::{HTMLTag, Node, Parser, ParserOptions};

use super::{Language, css, lexer};

pub(super) fn stream_context_candidates<F>(source: &[u8], sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let html = String::from_utf8_lossy(source);
    if html.trim().is_empty() {
        return Ok(());
    }

    let dom = match tl::parse(&html, ParserOptions::default()) {
        Ok(dom) => dom,
        Err(_) => return Ok(()),
    };
    let parser = dom.parser();

    for node in dom.nodes() {
        let Some(tag) = node.as_tag() else {
            continue;
        };
        let tag_name = tag.name().as_utf8_str().to_string();
        let normalized_tag_name = tag_name.to_ascii_lowercase();

        for (key, value) in tag.attributes().iter() {
            let Some(value) = value else {
                continue;
            };
            let candidate = format!("{key} = {value}");
            if !sink(&candidate) {
                return Ok(());
            }
        }

        match normalized_tag_name.as_str() {
            "script" => {
                let script_text = tag.inner_text(parser);
                let script_text = script_text.trim();
                if !script_text.is_empty() {
                    lexer::stream_context_candidates(
                        script_text.as_bytes(),
                        &Language::JavaScript,
                        sink,
                    )?;
                }
            }
            "style" => {
                let style_text = tag.inner_text(parser);
                let style_text = style_text.trim();
                if !style_text.is_empty() {
                    css::stream_context_candidates(style_text.as_bytes(), sink)?;
                }
            }
            _ => {
                let inner_text = text_without_embedded_code(tag, parser);
                if !inner_text.is_empty() && !sink(&format!("{tag_name} = {inner_text}")) {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

fn text_without_embedded_code(tag: &HTMLTag<'_>, parser: &Parser<'_>) -> String {
    let mut text = String::new();
    collect_visible_text(tag, parser, &mut text);
    text.trim().to_string()
}

fn collect_visible_text(tag: &HTMLTag<'_>, parser: &Parser<'_>, out: &mut String) {
    for handle in tag.children().top().iter() {
        let Some(node) = handle.get(parser) else {
            continue;
        };

        match node {
            Node::Raw(raw) => out.push_str(raw.as_utf8_str().as_ref()),
            Node::Comment(_) => {}
            Node::Tag(child) => {
                let child_name = child.name().as_utf8_str();
                if child_name.eq_ignore_ascii_case("script")
                    || child_name.eq_ignore_ascii_case("style")
                {
                    continue;
                }
                collect_visible_text(child, parser, out);
            }
        }
    }
}
