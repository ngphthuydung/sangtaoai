export const MAX_MEDIA_FILES_PER_BATCH = 5;
export const MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024;
export const MAX_AUDIO_SIZE_BYTES = 20 * 1024 * 1024;

export type MediaKind = 'image' | 'audio';

function isMpegFrame(bytes: Uint8Array, offset: number): boolean {
  if (offset + 4 > bytes.length) return false;
  const header = new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0);
  return (
    header >>> 21 === 0x7ff &&
    ((header >>> 19) & 0b11) !== 0b01 &&
    ((header >>> 17) & 0b11) !== 0 &&
    ![0, 15].includes((header >>> 12) & 0b1111) &&
    ((header >>> 10) & 0b11) !== 0b11
  );
}

async function hasMpegAudioHeader(file: File, bytes: Uint8Array): Promise<boolean> {
  if (bytes[0] === 0x49 && bytes[1] === 0x44 && bytes[2] === 0x33) {
    if (bytes.length < 10 || bytes[3] === 0xff || (bytes[5] & 0x0f) !== 0) {
      return false;
    }
    const tagSize =
      (bytes[6] << 21) | (bytes[7] << 14) | (bytes[8] << 7) | bytes[9];
    if ([6, 7, 8, 9].some((index) => (bytes[index] & 0x80) !== 0)) return false;
    const frameOffset = 10 + tagSize + ((bytes[5] & 0x10) !== 0 ? 10 : 0);
    if (frameOffset + 4 > file.size) return false;
    const frame = new Uint8Array(
      await file.slice(frameOffset, frameOffset + 4).arrayBuffer(),
    );
    return isMpegFrame(frame, 0);
  }
  for (let offset = 0; offset < Math.min(bytes.length, 4096); offset += 1) {
    if (isMpegFrame(bytes, offset)) return true;
  }
  return false;
}

export async function getMediaMimeType(
  file: File,
  kind: MediaKind,
): Promise<string> {
  const bytes = new Uint8Array(
    await file.slice(0, Math.min(file.size, 64 * 1024)).arrayBuffer(),
  );

  if (kind === 'image') {
    if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
      return 'image/jpeg';
    }
    if (
      bytes.length >= 8 &&
      bytes.subarray(0, 8).join(',') === '137,80,78,71,13,10,26,10'
    ) {
      return 'image/png';
    }
    if (
      bytes.length >= 12 &&
      new TextDecoder().decode(bytes.subarray(0, 4)) === 'RIFF' &&
      new TextDecoder().decode(bytes.subarray(8, 12)) === 'WEBP'
    ) {
      return 'image/webp';
    }
    throw new Error('Ảnh không đúng định dạng JPG, PNG hoặc WEBP.');
  }

  if (bytes.length >= 12 && (await hasMpegAudioHeader(file, bytes))) {
    return 'audio/mpeg';
  }
  if (
    bytes.length >= 12 &&
    new TextDecoder().decode(bytes.subarray(0, 4)) === 'RIFF' &&
    new TextDecoder().decode(bytes.subarray(8, 12)) === 'WAVE'
  ) {
    return 'audio/wav';
  }
  if (
    bytes.length >= 16 &&
    new TextDecoder().decode(bytes.subarray(4, 8)) === 'ftyp' &&
    ['M4A ', 'M4B ', 'M4P ', 'isom', 'iso2', 'mp41', 'mp42'].includes(
      String.fromCharCode(...bytes.subarray(8, 12)),
    )
  ) {
    return 'audio/mp4';
  }
  throw new Error('Tệp không đúng định dạng MP3, WAV hoặc M4A.');
}

export async function validateMediaFile(
  file: File,
  kind: MediaKind,
): Promise<string> {
  const maxBytes = kind === 'image' ? MAX_IMAGE_SIZE_BYTES : MAX_AUDIO_SIZE_BYTES;
  if (file.size === 0) throw new Error('Tệp trống.');
  if (file.size > maxBytes) {
    throw new Error(
      kind === 'image'
        ? 'Ảnh vượt quá giới hạn 10 MiB.'
        : 'Âm thanh vượt quá giới hạn 20 MiB.',
    );
  }
  return getMediaMimeType(file, kind);
}

export async function runSequentially<Item>(
  items: Item[],
  processItem: (item: Item) => Promise<void>,
): Promise<void> {
  for (const item of items) {
    await processItem(item);
  }
}
