import { appendFileSync, existsSync, readFileSync } from 'node:fs';

const [outFile, vault, item] = process.argv.slice(2);
if (outFile === undefined || vault === undefined || item === undefined) process.exit(2);

const send = (message: object): void => {
  const body = Buffer.from(JSON.stringify(message));
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length);
  process.stdout.write(Buffer.concat([header, body]));
};

const record = (message: unknown): void => {
  appendFileSync(outFile, `${JSON.stringify(message)}\n`);
};

const checkNonce = (value: unknown): { bytes: number; isFresh: boolean; isUrlSafe: boolean } => {
  const text = typeof value === 'string' ? value : '';
  const isUrlSafe = /^[A-Za-z0-9_-]+$/.test(text);
  const isFresh = readFileSync(outFile, 'utf8').split(`"nonce":"${text}"`).length === 2;
  return { bytes: Buffer.from(text, 'base64url').length, isFresh, isUrlSafe };
};

let pending = Buffer.alloc(0);
process.stdin.on('data', (chunk: Buffer) => {
  pending = Buffer.concat([pending, chunk]);
  while (pending.length >= 4) {
    const length = pending.readUInt32LE(0);
    if (pending.length < 4 + length) return;
    const message: unknown = JSON.parse(pending.subarray(4, 4 + length).toString('utf8'));
    pending = pending.subarray(4 + length);
    record(message);
    if (
      typeof message === 'object' &&
      message !== null &&
      Reflect.get(message, 'type') === 'unlock'
    ) {
      const id: unknown = Reflect.get(message, 'id');
      record({ type: 'unlock_check', ...checkNonce(Reflect.get(message, 'nonce')) });
      setTimeout(
        () => {
          send({ type: 'error', id: typeof id === 'number' ? id : null, code: 'declined' });
        },
        existsSync(`${outFile}.slow`) ? 2000 : 0,
      );
    }
    if (
      typeof message === 'object' &&
      message !== null &&
      Reflect.get(message, 'type') === 'page_reply'
    ) {
      send({ type: 'fill_request', id: 2, vault, item });
    }
  }
});

setTimeout(() => {
  send({ type: 'page_query', id: 1 });
}, 500);
