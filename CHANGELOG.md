# Changelog

All notable changes to this project will be documented in this file.

## [v0.6.2] - 2026-10-10

### Stability
* **Autoload hand-off**: waits up to 30s for elfldr (Relapse starts it slowly) and, if the loader accepts then drops the socket, sends the whole ELF again instead of failing the first short write.
* **Smaller ELF writes**: transfers go out in 16 KiB chunks so a single stalled syscall cannot throw away a multi-megabyte payload.
* **Cleared website data**: if the offline cache is still present but `localStorage` was wiped, a single-chain console launches the only chain it can run, and a dual-chain console asks again. Neither path re-downloads the cache or re-runs the installer. A stored chain this firmware cannot run is ignored, so a Poops choice cannot be launched on 12.02+.
* **Installer memory**: each compressed file is inflated once and reused. Parallel AppCache fetches no longer keep eight copies of the chain pages in memory.
* **Duplicate install**: a second `/install` waits for the first instead of installing the homescreen app twice or reporting a false failure.
* **Stuck cache**: a download that stops making progress, or a check that never starts, offers the existing repair instead of sitting on "Caching..." until the console is rebooted.
* **Previous installer**: process scan no longer reads off the end of the kernel process list, and a copy that will not die is reported instead of slept on forever.
* **Unreadable firmware**: a PlayStation user agent with no version is treated as unsupported. Guessing both chains was a kernel panic on firmware the table does not know.

## [v0.6.1] - 2026-10-08

* **9.05, 11.40 & 11.60**: Added missing offsets to fix Poops support.
  *(Note: Relapse remains unsupported on 9.05 and 11.40)*

## [v0.6.0] - 2026-10-07

### Unified Architecture & Upstream Remote Loader Base
* **Single Shared Base**: WebKit Autoloader is now built on top of [ps5-webkit-remote-loader](https://github.com/itsPLK/ps5-webkit-remote-loader), unifying the userland exploit runner, ROP primitives, and payload pipeline across both Poops and Relapse.
* **Developer Iteration & Contributions**: Developers looking to experiment with, test, or improve Poops or Relapse can now do so easily in [ps5-webkit-remote-loader](https://github.com/itsPLK/ps5-webkit-remote-loader) by loading payloads over the network (port 9027). Any improvements made in that repo can be contributed upstream to directly benefit both projects.

### Dropped umtx2 (FW <= 5.50)
* **Dropped Legacy umtx2 Support**: Support for firmwares 1.00–5.50 via umtx2 has been dropped in this release. That path was not receiving updates and was blocking development and architectural changes.
* **Future Lower Firmware Support**: Support for lower firmwares may be added back in the future if it is added to [ps5-webkit-remote-loader](https://github.com/itsPLK/ps5-webkit-remote-loader). Contributions to bring lower firmware support to the new unified base are welcome!

### Exploit & Stability Improvements
* **Relapse Stability**: Stability and reliability improvements for the Relapse chain.

---
For changelogs of previous releases, see [GitHub Releases](https://github.com/itsPLK/ps5-webkit-autoloader/releases).

