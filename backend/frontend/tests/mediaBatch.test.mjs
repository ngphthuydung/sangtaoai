import assert from 'node:assert/strict';
import test from 'node:test';

import {
  MAX_AUDIO_SIZE_BYTES,
  MAX_IMAGE_SIZE_BYTES,
  MAX_MEDIA_FILES_PER_BATCH,
  getMediaMimeType,
  runSequentially,
  validateMediaFile,
} from '../src/mediaBatch.ts';

function makeFile(name, bytes, type = '') {
  return new File([Uint8Array.from(bytes)], name, { type });
}

test('identifies media using file signatures instead of the filename MIME type', async () => {
  const jpeg = makeFile('misleading.png', [0xff, 0xd8, 0xff, 0x00], 'image/png');
  const png = makeFile(
    'photo.bin',
    [137, 80, 78, 71, 13, 10, 26, 10, 0],
    'application/octet-stream',
  );
  const mp3 = makeFile(
    'recording.mp3',
    [73, 68, 51, 4, 0, 0, 0, 0, 0, 0, 0xff, 0xfb, 0x90, 0x64],
  );

  assert.equal(await getMediaMimeType(jpeg, 'image'), 'image/jpeg');
  assert.equal(await getMediaMimeType(png, 'image'), 'image/png');
  assert.equal(await getMediaMimeType(mp3, 'audio'), 'audio/mpeg');
});

test('rejects unknown formats and media over the explicit per-file limits', async () => {
  await assert.rejects(
    getMediaMimeType(makeFile('fake.jpg', [0, 1, 2]), 'image'),
    /không đúng định dạng/,
  );
  await assert.rejects(
    validateMediaFile(makeFile('empty.mp3', []), 'audio'),
    /Tệp trống/,
  );

  const oversizedImage = new File([new Uint8Array(MAX_IMAGE_SIZE_BYTES + 1)], 'big.png');
  const oversizedAudio = new File([new Uint8Array(MAX_AUDIO_SIZE_BYTES + 1)], 'big.mp3');
  await assert.rejects(validateMediaFile(oversizedImage, 'image'), /10 MiB/);
  await assert.rejects(validateMediaFile(oversizedAudio, 'audio'), /20 MiB/);
  assert.equal(MAX_MEDIA_FILES_PER_BATCH, 5);
});

test('rejects ID3 metadata without an MP3 audio frame', async () => {
  const invalidMp3 = makeFile(
    'empty-audio.mp3',
    [73, 68, 51, 4, 0, 0, 0, 0, 0, 0, 110, 111],
  );
  await assert.rejects(getMediaMimeType(invalidMp3, 'audio'), /không đúng định dạng/);
});

test('processes batch items sequentially while allowing an individual failure', async () => {
  let active = 0;
  let maxActive = 0;
  const completed = [];

  await runSequentially(['first', 'second', 'third'], async (item) => {
    active += 1;
    maxActive = Math.max(maxActive, active);
    await Promise.resolve();
    if (item !== 'second') completed.push(item);
    active -= 1;
  });

  assert.equal(maxActive, 1);
  assert.deepEqual(completed, ['first', 'third']);
});
