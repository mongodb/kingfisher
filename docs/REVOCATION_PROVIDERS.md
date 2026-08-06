# Revocation Support Matrix

Kingfisher supports direct secret revocation through rule-level `revocation:` blocks.

Current coverage in built-in rules:
- `36` provider families
- `60` revocation-enabled rules

Use `kingfisher revoke --rule <rule-id> <secret>` to invoke these flows. See [USAGE.md](USAGE.md#direct-secret-revocation-with-kingfisher-revoke) for command details.

## Supported Providers

| Provider | Revocation Rule Count | Rule IDs |
|---|---:|---|
| `aws` | 1 | `kingfisher.aws.2` |
| `browserstack` | 1 | `kingfisher.browserstack.1` |
| `buildkite` | 1 | `kingfisher.buildkite.1` |
| `cloudflare` | 1 | `kingfisher.cloudflare.1` |
| `confluent` | 2 | `kingfisher.confluent.2`, `kingfisher.confluent.3` |
| `cratesio` | 1 | `kingfisher.cratesio.1` |
| `deviantart` | 1 | `kingfisher.deviantart.1` |
| `digitalocean` | 1 | `kingfisher.digitalocean.1` |
| `discord` | 1 | `kingfisher.discord.1` |
| `doppler` | 6 | `kingfisher.doppler.1`, `kingfisher.doppler.2`, `kingfisher.doppler.3`, `kingfisher.doppler.4`, `kingfisher.doppler.5`, `kingfisher.doppler.6` |
| `falai` | 1 | `kingfisher.falai.1` |
| `gcp` | 1 | `kingfisher.gcp.1` |
| `github` | 7 | `kingfisher.github.1`, `kingfisher.github.2`, `kingfisher.github.3`, `kingfisher.github.4`, `kingfisher.github.5`, `kingfisher.github.6`, `kingfisher.github.9` |
| `gitlab` | 2 | `kingfisher.gitlab.1`, `kingfisher.gitlab.4` |
| `google` | 1 | `kingfisher.google.4` |
| `harness` | 1 | `kingfisher.harness.pat.1` |
| `heroku` | 2 | `kingfisher.heroku.1`, `kingfisher.heroku.2` |
| `jira` | 1 | `kingfisher.jira.3` |
| `launchdarkly` | 1 | `kingfisher.launchdarkly.1` |
| `linode` | 1 | `kingfisher.linode.1` |
| `mapbox` | 1 | `kingfisher.mapbox.2` |
| `mongodb` | 1 | `kingfisher.mongodb.1` |
| `netlify` | 2 | `kingfisher.netlify.1`, `kingfisher.netlify.2` |
| `npm` | 2 | `kingfisher.npm.1`, `kingfisher.npm.2` |
| `particleio` | 2 | `kingfisher.particleio.1`, `kingfisher.particleio.2` |
| `resend` | 1 | `kingfisher.resend.api_key.1` |
| `sendgrid` | 1 | `kingfisher.sendgrid.1` |
| `slack` | 4 | `kingfisher.slack.1`, `kingfisher.slack.2`, `kingfisher.slack.7`, `kingfisher.slack.8` |
| `sumologic` | 1 | `kingfisher.sumologic.2` |
| `tailscale` | 1 | `kingfisher.tailscale.1` |
| `twilio` | 1 | `kingfisher.twilio.2` |
| `twitch` | 1 | `kingfisher.twitch.1` |
| `unkey` | 1 | `kingfisher.unkey.2` |
| `vercel` | 5 | `kingfisher.vercel.1`, `kingfisher.vercel.2`, `kingfisher.vercel.3`, `kingfisher.vercel.4`, `kingfisher.vercel.5` |
| `vonage` | 1 | `kingfisher.vonage.2` |
| `vultr` | 1 | `kingfisher.vultr.1` |

## Notes

- Coverage above is derived from built-in YAML rules under `crates/kingfisher-rules/data/rules/` that currently define a `revocation:` block.
- A provider may have additional detection/validation rules that do not yet support revocation.
