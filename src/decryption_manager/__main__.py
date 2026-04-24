try:
    # Normal package execution: python -m decryption_manager
    from .cli import run
except ImportError:
    # Frozen/packaged entrypoint fallback (PyInstaller on some builds)
    from decryption_manager.cli import run


if __name__ == "__main__":
    run()
