#!/usr/bin/env python3
"""Serve one frozen, full-history Git snapshot and identical pack bytes to both clients.

This is a benchmark-only smart-HTTP v0 replay, NOT a general purpose Git server.
It serves the self-contained pack from a fresh mirror clone. Run only against
trusted local benchmark repositories, with fresh mirror-clone clients.

  python3 scripts/serve-git-clone-snapshot.py --repository SOURCE.git \
    --output target/clone-benchmark/replay

The printed loopback URL can be passed to benchmark-git-clone.py --url. Requests
are not timed on the server and no git-upload-pack subprocess runs during clones.
"""
import argparse
import gzip
import hashlib
import http.server
import json
import pathlib
import shutil
import subprocess
import urllib.parse


def packet(data):
    return f"{len(data) + 4:04x}".encode("ascii") + data


def prepare(repository, output):
    git = shutil.which("git")
    def query(*args):
        return subprocess.check_output([git, "-C", str(repository), *args])
    if query("rev-parse", "--show-object-format").strip() != b"sha1":
        raise ValueError("replay currently supports SHA-1 repositories only")
    packs = list((repository / "objects/pack").glob("*.pack"))
    if len(packs) != 1:
        raise ValueError("snapshot must have exactly one self-contained pack; fresh mirror required")
    pack = packs[0]
    output.mkdir(parents=True, exist_ok=False)
    head = query("rev-parse", "HEAD").strip()
    target = query("symbolic-ref", "HEAD").strip()
    capabilities = (b"multi_ack_detailed side-band-64k thin-pack ofs-delta no-progress include-tag "
                    b"object-format=sha1 symref=HEAD:" + target + b" agent=kingfisher-benchmark")
    advertisement = packet(b"# service=git-upload-pack\n") + b"0000"
    advertisement += packet(head + b" HEAD\0" + capabilities + b"\n")
    refs = query("show-ref", "--dereference").splitlines()
    for ref in refs:
        advertisement += packet(ref + b"\n")
    advertisement += b"0000"
    (output / "advertisement.bin").write_bytes(advertisement)
    response = output / "response.bin"
    digest = hashlib.sha256()
    with pack.open("rb") as source, response.open("xb") as destination:
        header = source.read(12)
        if header[:4] != b"PACK":
            raise ValueError("invalid source pack")
        object_count = int.from_bytes(header[8:12], "big")
        source.seek(0)
        prefix = packet(b"NAK\n")
        destination.write(prefix)
        digest.update(prefix)
        while chunk := source.read(65515):
            framed = packet(b"\x01" + chunk)
            destination.write(framed)
            digest.update(framed)
        destination.write(b"0000")
        digest.update(b"0000")
        source.seek(-20, 2)
        pack_id = source.read().hex()
    metadata = {"repository": str(repository), "pack": str(pack), "pack_sha1": pack_id,
                "pack_bytes": pack.stat().st_size, "pack_objects": object_count,
                "advertised_ref_lines": len(refs) + 1, "head": head.decode(),
                "response_bytes": response.stat().st_size,
                "response_sha256": digest.hexdigest(), "protocol": "smart HTTP v0, side-band-64k"}
    (output / "snapshot.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return advertisement, response, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repository", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    advertisement, response, metadata = prepare(args.repository.resolve(strict=True), args.output.resolve())

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def send(self, content, kind):
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            if url.path == "/mongo.git/info/refs" and url.query == "service=git-upload-pack":
                self.send(advertisement, "application/x-git-upload-pack-advertisement")
            else:
                self.send_error(404)

        def read_request(self):
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                chunks = []
                size = int(self.rfile.readline().split(b";", 1)[0], 16)
                while size:
                    chunks.append(self.rfile.read(size))
                    if self.rfile.read(2) != b"\r\n":
                        raise ValueError("invalid chunk terminator")
                    size = int(self.rfile.readline().split(b";", 1)[0], 16)
                while trailer := self.rfile.readline():
                    if trailer == b"\r\n":
                        break
                return b"".join(chunks)
            return self.rfile.read(int(self.headers.get("Content-Length", "0")))

        def do_POST(self):
            if self.path != "/mongo.git/git-upload-pack":
                self.send_error(404)
                return
            body = self.read_request()
            encoding = self.headers.get("Content-Encoding", "").lower()
            if encoding == "gzip":
                body = gzip.decompress(body)
            elif encoding:
                self.send_error(415, "unsupported request encoding")
                return
            if b"have " in body or b"done\n" not in body or b"side-band-64k" not in body:
                self.send_error(400, "replay supports only fresh full clones with side-band-64k")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/x-git-upload-pack-result")
            self.send_header("Content-Length", str(response.stat().st_size))
            self.end_headers()
            with response.open("rb") as stream:
                shutil.copyfileobj(stream, self.wfile, 1024 * 1024)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    metadata["url"] = f"http://127.0.0.1:{server.server_port}/mongo.git"
    (args.output / "server.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(metadata), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
