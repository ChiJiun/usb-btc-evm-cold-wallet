// Test adapter: raw Python JSON -> actual UR encoder/decoder -> exact JSON integers.
import { encodeFrames, BoundedURScanner, serializeEnvelope } from "../src/ur_transport.mjs";

let json = "";
for await (const chunk of process.stdin) json += chunk;
const scanner = new BoundedURScanner();
const frames = encodeFrames(json, { fragmentBytes: 220 });
for (const frame of frames) {
  const result = scanner.add(frame);
  if (result.done) break;
}
if (!scanner.done) throw new Error("Python/browser QR fixture was not completed");
process.stdout.write(serializeEnvelope(scanner.payload));
