// Third payload in each chain page. The exploit runs second and brings up elfldr
// on port 9021, so this only has to stage the ELF and hand it over. No chain
// selection happens here: the page is already built for one chain.
//
// Resources are embedded by remote-loader's builder, so the fetch below is
// served from the page itself and still works after the exploit has taken the
// process over.
const NR = { SOCKET: 0x61, CONNECT: 0x62, WRITE: 4, CLOSE: 6, MMAP: 0x1dd, MUNMAP: 0x49 };

// Relapse brings the loader up slowly on purpose. 120 * 250ms is half a minute,
// which covers that without spinning forever when nothing is listening.
const CONNECT_TRIES = 120;
const CONNECT_WAIT_MS = 250;
// A listener that accepts and then drops the socket (loader still starting) must
// be given a fresh connection and the whole file again. Resuming mid-file on a
// new connection is not a valid ELF.
const HANDOFFS = 4;
const WRITE_CHUNK = 0x4000;
const WRITE_STALLS = 4;

function failed(value) {
  return (value.low | 0) === -1;
}

function pause(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function connect(api) {
  const socket = await api.chain.syscall(NR.SOCKET, 2, 1, 0);
  if (failed(socket)) return -1;
  const fd = socket.low | 0;
  const addr = api.p.malloc(16, 1);
  for (let i = 0; i < 16; i++) api.p.write1(addr.add32(i), 0);
  // sockaddr_in: length, AF_INET, port 9021, loopback address.
  [16, 2, 0x23, 0x3d, 127, 0, 0, 1].forEach((v, i) => api.p.write1(addr.add32(i), v));
  try {
    const result = await api.chain.syscall(NR.CONNECT, fd, addr, 16);
    if ((result.low | 0) === 0) return fd;
  } catch (error) {
    await api.chain.syscall(NR.CLOSE, fd);
    throw error;
  }
  await api.chain.syscall(NR.CLOSE, fd);
  return -1;
}

async function closeFd(api, fd) {
  if (fd < 0) return;
  try { await api.chain.syscall(NR.CLOSE, fd); } catch (error) { /* already closed */ }
}

async function loadElf(api) {
  const elfName = (api && Array.isArray(api.args) && api.args[0]) || "autoload.elf";
  const response = await fetch(elfName);
  if (!response.ok) throw new Error("Could not load " + elfName + ".");
  const bytes = await response.arrayBuffer();
  const view = new DataView(bytes);
  if (bytes.byteLength < 0x1000 || view.getUint32(0, true) !== 0x464c457f)
    throw new Error(elfName + " is not an ELF binary.");
  const size = bytes.byteLength;
  const mapped = Math.ceil(size / 0x4000) * 0x4000;
  const base = await api.chain.syscall(NR.MMAP, 0, mapped, 3, 0x1002, -1, 0);
  if (failed(base)) throw new Error("Could not map " + elfName + ".");
  try {
    let i = 0;
    for (; i + 4 <= size; i += 4) api.p.write4(base.add32(i), view.getUint32(i, true));
    for (; i < size; i++) api.p.write1(base.add32(i), view.getUint8(i));
    if ((api.p.read4(base) >>> 0) !== 0x464c457f)
      throw new Error(elfName + " copy failed.");
    return { name: elfName, base, size, mapped };
  } catch (error) {
    await api.chain.syscall(NR.MUNMAP, base, mapped);
    throw error;
  }
}

async function sendElf(api, elf) {
  let lastError = null;
  for (let handoff = 0; handoff < HANDOFFS; handoff++) {
    let fd = -1;
    try {
      for (let attempt = 0; attempt < CONNECT_TRIES; attempt++) {
        fd = await connect(api);
        if (fd >= 0) break;
        await pause(CONNECT_WAIT_MS);
      }
      if (fd < 0) throw new Error("The ELF loader did not start on port 9021.");
      let sent = 0;
      let stalls = 0;
      while (sent < elf.size) {
        const want = Math.min(WRITE_CHUNK, elf.size - sent);
        const result = await api.chain.syscall(NR.WRITE, fd, elf.base.add32(sent), want);
        const count = result.low | 0;
        // A zero or negative count is a dropped loader, not a finished file.
        // A few stalls on the same socket are retried; then the whole ELF is
        // sent again on a new connection.
        if (count <= 0 || count > want) {
          if (++stalls >= WRITE_STALLS)
            throw new Error("ELF transfer failed after " + sent + " bytes.");
          await pause(50);
          continue;
        }
        stalls = 0;
        sent += count;
      }
      await api.log("Autoload: sent " + sent + " bytes of " + elf.name + " to elfldr.", "success");
      await closeFd(api, fd);
      return;
    } catch (error) {
      lastError = error;
      await closeFd(api, fd);
      if (handoff + 1 < HANDOFFS) await pause(300);
    }
  }
  throw lastError;
}

return async function (api) {
  // Payload three of three, so the exploit has already run. If it did not publish
  // kernel access then nothing was achieved and no ELF should be sent.
  if (!api.krw) throw new Error("The exploit did not complete; no ELF was sent.");

  const elf = await loadElf(api);
  await api.log("Autoload: staging " + elf.name + " (" + elf.size + " bytes)...", "info");
  try {
    await sendElf(api, elf);
  } finally {
    await api.chain.syscall(NR.MUNMAP, elf.base, elf.mapped);
  }
};
