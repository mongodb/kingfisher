# Kingfisher visual demos

The investigation walkthrough uses real viewer screenshots and the synthetic
[investigation report](../viewer/investigation-demo.json). It shows authorization evidence and
the resource map. Screen transitions illustrate the workflow; this is not a recording
of a live scan or a real account assessment.

Regenerate the captioned GIF from the checked-in screenshots:

```bash
python3 docs/demos/make-investigation-demo.py docs/demos/investigation-demo.json \
  --font /path/to/DejaVuSans.ttf \
  --output docs/assets/screenshots/investigation-walkthrough.gif --overwrite
```

Replace the font path with an installed TTF/OTF font; the checked-in animation uses DejaVu Sans.
The encoder requires FFmpeg, processes one scene at a time, and limits encoding threads.
Captions identify the data as synthetic. Keep the existing static screenshots as alternatives
for readers who prefer no animation. Do not include usable credentials or imply that synthetic
findings are live validation results.

