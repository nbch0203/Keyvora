// Generates the extension icons (PNG) at build time so that no binary files live in the repository.
import { deflateSync } from "node:zlib";

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

function encodePng(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/** Shape in unit coordinates: 0 = transparent, 1 = background, 2 = key (white). */
function shape(u, v) {
  const r = 0.2;
  const inRounded = (() => {
    const cx = Math.min(Math.max(u, r), 1 - r);
    const cy = Math.min(Math.max(v, r), 1 - r);
    return (u - cx) ** 2 + (v - cy) ** 2 <= r * r;
  })();
  if (!inRounded) return 0;
  const d = Math.hypot(u - 0.34, v - 0.5);
  const ring = d <= 0.19 && d >= 0.08;
  const shaft = u >= 0.48 && u <= 0.84 && v >= 0.45 && v <= 0.55;
  const tooth1 = u >= 0.66 && u <= 0.72 && v >= 0.55 && v <= 0.66;
  const tooth2 = u >= 0.76 && u <= 0.84 && v >= 0.55 && v <= 0.7;
  return ring || shaft || tooth1 || tooth2 ? 2 : 1;
}

export function iconPng(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const S = 4; // supersampling
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let bg = 0;
      let key = 0;
      for (let sy = 0; sy < S; sy++) {
        for (let sx = 0; sx < S; sx++) {
          const s = shape((x + (sx + 0.5) / S) / size, (y + (sy + 0.5) / S) / size);
          if (s === 1) bg++;
          else if (s === 2) key++;
        }
      }
      const total = S * S;
      const a = (bg + key) / total;
      const k = bg + key === 0 ? 0 : key / (bg + key);
      const i = (y * size + x) * 4;
      rgba[i] = Math.round(0x2f + (0xff - 0x2f) * k);
      rgba[i + 1] = Math.round(0x45 + (0xff - 0x45) * k);
      rgba[i + 2] = Math.round(0xc5 + (0xff - 0xc5) * k);
      rgba[i + 3] = Math.round(255 * a);
    }
  }
  return encodePng(size, rgba);
}

export const ICON_SIZES = [16, 32, 48, 128];
