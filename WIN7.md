# OsTIrus 1.4.2 for Windows 7 (Ableton Live 10 x64)

This tree is a **patch overlay** on [gearmulator 1.4.2](https://github.com/dsp56300/gearmulator/releases/tag/1.4.2) (JUCE 7, last GUI meant for Windows 7). GitHub Actions checks out that tag with submodules, copies `overlay/`, and builds **64-bit VST2 + VST3**.

## GitHub Actions (Windows 7 x64 plugins)

Create a **new** GitHub repository (private is fine). Do not push this tree to `dsp56300/gearmulator`. If `git log` does not work yet, the upstream clone is still incomplete — keep `overlay/`, `scripts/`, `.github/`, and `WIN7.md` and put those in the new repo.

```bash
git remote rename origin upstream   # if origin still points at dsp56300/gearmulator
git remote add origin git@github.com:<you>/ostirus-win7.git
git add overlay scripts .github WIN7.md .gitignore
git commit -m "OsTIrus 1.4.2 Win7 overlay and MSVC v143 build"
git push -u origin main
```

The `OsTIrus 1.4.2 Windows 7 x64` workflow checks out gearmulator **1.4.2** with submodules, applies `overlay/`, and uploads `OsTIrus.dll` (VST2) plus `OsTIrus.vst3`.

License: same as gearmulator (**GPL-3.0**). Do not bundle Virus TI firmware ROMs.


## Install on Windows 7 x64

1. Download the `OsTIrus-1.4.2-win7-x64-VST2-VST3` artifact zip from GitHub Actions.
2. Copy `OsTIrus.dll` to your Live 10 VST2 folder (often `C:\Program Files\VSTPlugins` or Live’s custom VST2 path).
3. Copy the `OsTIrus.vst3` folder to `C:\Program Files\Common Files\VST3`.
4. Rescan plug-ins in Live 10.

## What the overlay changes

- Patch Manager **Categories (N)** is the number of **patches that have a category tag**, not the number of category names (Virus TI still has a fixed Category1/Category2 name list).
- Files up to **512 MB** are imported (the old **8 MB** skip dropped large `.mid` / `.syx` / TI backups).
- Category searches refresh when `anyTagOfType` / `noTagOfType` change.
- The tree paints the count on the right so large numbers are not clipped.
- Windows 7 target (`_WIN32_WINNT=0x0601`), static `/MT` CRT, per-monitor DPI **off**, PE subsystem **6.1**.

## Test in Live 10 (Windows 7)

- Both VST2 and VST3 appear after a rescan.
- Editor opens without multi-second lag on knobs/clicks.
- Audio plays with your existing TI ROM.
- Patch Manager → Categories (N) matches categorized patches after adding/removing banks, including large files.
- Close/reopen the editor; the count stays correct.
