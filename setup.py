"""Build hook: compile the vendored C into libtab/libtab.so at install /
wheel-build time.

py-libtab is a ctypes binding, not a CPython C-extension, so there is no
extension module to compile in the usual way. But we still need pip / a
wheel build to (1) run the real C compile (vendor/build.sh) and (2)
produce a *platform* wheel (not py3-none-any), since the shipped .so is
architecture-specific. We do both with a dummy Extension that forces the
platform tag, plus a custom build_ext that ignores the dummy and instead
runs vendor/build.sh and copies the resulting libtab.so into the built
package.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

HERE = os.path.dirname(os.path.abspath(__file__))


class BuildLibtabSo(build_ext):
    def run(self) -> None:
        build_sh = os.path.join(HERE, "vendor", "build.sh")
        if not os.path.exists(build_sh):
            raise RuntimeError(f"vendor/build.sh missing at {build_sh}")

        # Compile vendored plan9port + libtab.c + monocypher -> vendor/libtab.so
        subprocess.run(["bash", build_sh], check=True, cwd=HERE)

        built_so = os.path.join(HERE, "vendor", "libtab.so")
        if not os.path.exists(built_so):
            raise RuntimeError("vendor/build.sh did not produce vendor/libtab.so")

        # Place it inside the built package: <build_lib>/libtab/libtab.so.
        # self.build_lib is where setuptools assembles the package for the
        # wheel; copying here makes _find_so() find it in the installed
        # package (its first search location).
        dest_dir = os.path.join(self.build_lib, "libtab")
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, "libtab.so")
        shutil.copy2(built_so, dest)
        self.announce(f"placed native library at {dest}", level=2)


setup(
    # A dummy, never-actually-compiled Extension. Its only jobs: force a
    # non-pure (platform-specific) wheel tag, and give build_ext something
    # to run. The custom command above ignores it and runs build.sh.
    ext_modules=[Extension(name="libtab._libtab_native_placeholder", sources=[])],
    cmdclass={"build_ext": BuildLibtabSo},
)
