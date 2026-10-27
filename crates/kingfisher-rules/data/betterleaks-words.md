# Betterleaks token-efficiency wordlist

`betterleaks-words.txt.gz` is copied without modification from
[Betterleaks v2.0.0-rc.1](https://github.com/betterleaks/betterleaks/blob/b3b4cbb586c964701f78bbfb6bc2129ced99bed3/internal/words/words.txt.gz).
It is used by the imported `failsTokenEfficiency` helper, including the upstream
case-insensitive substring checks and length-sensitive thresholds.

Source SHA-256: `d4dd5530d98f4ff343864ed71cfc0064abeae34e4f078edc0b46590c2da8fb47`.
The Betterleaks code is covered by its MIT license, retained with the generated
rule-source notices. The wordlist data has separate attribution and licensing:
the [original Betterleaks source](https://github.com/betterleaks/betterleaks/blob/5f0535ee337f4b0a514e71b271b426c2bb33311f/words/words.go)
identifies it as common English words longer than three characters from
**wordfreq, Copyright 2022 Robyn Speer**. Betterleaks selected this subset; this
copy is unchanged. Despite the upstream variable name `nltkWords`, the source
identifies wordfreq as its origin.

The wordlist data is distributed under **CC-BY-SA-4.0**, independently of the
Rust source license. Retain [wordfreq's attribution notices](wordfreq-NOTICE.md)
and the [CC-BY-SA-4.0 license](wordfreq-LICENSE.txt) with redistributed data and
adaptations. The notices credit the freely available SUBTLEX data by Marc
Brysbaert and colleagues and the other corpus contributors. The notices were
archived from [wordfreq](https://github.com/rspeer/wordfreq/blob/912caf64b657478d1dff1138efdc078947d54bb1/NOTICE.md).
