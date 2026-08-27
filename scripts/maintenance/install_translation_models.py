"""
One-off setup script, not part of the automated pipeline (run from the
repository root).

Downloads and installs the Argos Translate language models this project
uses (zh/ru/fr -> en, for CNVD/FSTEC/CERT-FR - see core/translation.py).
Run once after `pip install -r requirements-translation.txt`; models are
cached locally afterwards and translation runs fully offline.

Requires argostranslate to be installed (requirements-translation.txt) -
this script is only useful once that's done.
"""

import sys

LANGUAGE_PAIRS = [("zh", "en"), ("ru", "en"), ("fr", "en")]


def main():
    try:
        import argostranslate.package
    except ImportError:
        print(
            "argostranslate is not installed. Install it first with:\n"
            "  pip install -r requirements-translation.txt"
        )
        sys.exit(1)

    print("Updating Argos Translate package index...")
    argostranslate.package.update_package_index()
    available = argostranslate.package.get_available_packages()

    for from_code, to_code in LANGUAGE_PAIRS:
        pkg = next(
            (p for p in available if p.from_code == from_code and p.to_code == to_code),
            None,
        )
        if not pkg:
            print(f"[WARN] No {from_code}->{to_code} package found in the Argos index, skipping.")
            continue

        print(f"Downloading {from_code}->{to_code} model...")
        path = pkg.download()
        argostranslate.package.install_from_path(path)
        print(f"  Installed {from_code}->{to_code}.")

    print("\nDone. Installed languages:")
    import argostranslate.translate
    for lang in argostranslate.translate.get_installed_languages():
        print(f"  - {lang.code} ({lang.name})")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
