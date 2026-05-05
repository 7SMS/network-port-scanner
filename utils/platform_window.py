"""
Platform-specific window appearance tweaks.

Currently implements Windows dark mode title bar via the DWM (Desktop Window
Manager) API. This is the same mechanism used by VS Code, Discord, and other
modern dark-themed apps on Windows.

How it works:
  - Windows 10 build 17763+ exposes DwmSetWindowAttribute with attribute
    DWMWA_USE_IMMERSIVE_DARK_MODE (initially #19, later renamed to #20).
  - Setting it to TRUE asks the DWM to render the title bar in dark mode.
  - The window must already have a HWND (be shown at least once) before we
    can apply this — Qt creates the HWND lazily.

This function is a no-op on:
  - Non-Windows platforms (macOS / Linux)
  - Windows versions older than 10
  - Failure cases (we never raise — visual polish must not crash the app)

For full control over title bar color (custom hex value), there is no
official Windows API. The only options are:
  1. Live with whatever DWM picks (this function — accepted approach)
  2. Use a frameless window and draw your own title bar (heavy, breaks
     window snapping and other Windows shell integrations)

We chose option 1 because option 2's cost outweighs the benefit.
"""

from __future__ import annotations

import sys


def apply_dark_titlebar(window) -> bool:
    """
    Try to make the given window's title bar dark on Windows.

    Returns True on success, False otherwise. Never raises.
    Call this AFTER window.show() — the HWND must exist.
    """
    if not sys.platform.startswith("win"):
        return False

    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return False

    try:
        # Get the native window handle from the Qt widget.
        hwnd = int(window.winId())
        if not hwnd:
            return False

        dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
        DwmSetWindowAttribute = dwmapi.DwmSetWindowAttribute
        DwmSetWindowAttribute.argtypes = [
            wintypes.HWND, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD,
        ]
        DwmSetWindowAttribute.restype = ctypes.c_long  # HRESULT

        value = ctypes.c_int(1)  # TRUE = enable dark mode

        # Try the modern attribute ID first (Windows 10 20H1+).
        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        hr = DwmSetWindowAttribute(
            hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
            ctypes.byref(value), ctypes.sizeof(value),
        )
        if hr == 0:
            return True

        # Fall back to the older attribute ID (1809 / 17763).
        DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19
        hr = DwmSetWindowAttribute(
            hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD,
            ctypes.byref(value), ctypes.sizeof(value),
        )
        return hr == 0
    except Exception:  # noqa: BLE001 — visual polish never crashes the app
        return False
