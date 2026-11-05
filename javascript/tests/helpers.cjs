'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const zlib = require('node:zlib');
const { Rules } = require('../index.cjs');

const TOKEN = 'kf_a9B2c7D4e1F8g3H6';
function temporary() { return fs.mkdtempSync(path.join(process.env.KINGFISHER_TEST_TMPDIR ?? os.tmpdir(), 'kingfisher-js-')); }
function ruleYaml(extra = '', id = 'acme.node-token') {
  return `rules:
  - id: ${id}
    name: Acme Node token
    pattern: '\\b(kf_[A-Za-z0-9]{16})\\b'
    min_entropy: 0
    examples:
      - ${TOKEN}
${extra}`;
}
async function rulesIn(directory, extra = '', id = 'acme.node-token', filename = 'rules.yml') {
  const file = path.join(directory, filename);
  fs.writeFileSync(file, ruleYaml(extra, id));
  return await Rules.load({ paths: [file], builtins: false, cache: false });
}
async function server(handler) {
  const sockets = new Set();
  const instance = http.createServer(handler);
  instance.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise((resolve, reject) => { instance.once('error', reject); instance.listen(0, '127.0.0.1', resolve); });
  return {
    url: `http://127.0.0.1:${instance.address().port}`,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => instance.close(resolve));
    },
  };
}
function httpRule(url, revokeUrl = `${url}/revoke`) {
  return `    validation:
      type: Http
      content:
        request:
          method: GET
          url: '${url}/identity'
          headers:
            Authorization: 'Bearer {{ TOKEN }}'
          response_matcher:
            - type: StatusMatch
              status: [200]
            - type: WordMatch
              words: ['"authenticated":true']
    revocation:
      type: Http
      content:
        request:
          method: POST
          url: '${revokeUrl}'
          headers:
            Authorization: 'Bearer {{ TOKEN }}'
          response_matcher:
            - type: StatusMatch
              status: [204]
`;
}
function zip(entries) {
  const records = [];
  const directory = [];
  let offset = 0;
  for (const [name, value] of entries) {
    const filename = Buffer.from(name);
    const data = Buffer.from(value);
    const compressed = zlib.deflateRawSync(data);
    let crc = 0xffffffff;
    for (const byte of data) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
    crc = (~crc) >>> 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x800, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(filename.length, 26);
    records.push(local, filename, compressed);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(filename.length, 28);
    central.writeUInt32LE(offset, 42);
    directory.push(central, filename);
    offset += local.length + filename.length + compressed.length;
  }
  const central = Buffer.concat(directory);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...records, central, end]);
}
module.exports = { TOKEN, temporary, ruleYaml, rulesIn, server, httpRule, zip };
