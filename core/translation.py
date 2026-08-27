"""
Offline translation of non-English threat entries (CNVD/FSTEC/CERT-FR) via
Argos Translate.

Argos Translate is an OPTIONAL dependency (see requirements-translation.txt,
not requirements.txt) - importing this module never fails even if it isn't
installed. Every function here degrades to a no-op (returns None / leaves
fields untranslated) rather than raising, so a scraper or pipeline run never
crashes because translation isn't set up. See INSTALLATION.md for how to
enable it.

Per-field policy: which fields get translated for a given source language.
Chinese (CNVD) titles are deliberately excluded - diagnostic testing (Vague
3a) showed the model drops security-critical detail in short zh titles
(e.g. "buffer overflow" disappearing, filenames getting truncated), while
descriptions stay usable. Only add a language here once its translation
quality has been checked on real samples the same way.
"""

from datetime import datetime

try:
    import argostranslate.translate
    TRANSLATION_AVAILABLE = True
except ImportError:
    TRANSLATION_AVAILABLE = False

FIELDS_TO_TRANSLATE = {
    "zh": ("description",),
    "ru": ("title", "description"),
    "fr": ("title", "description"),
}

# Emitted at most once per process, so a pipeline run translating 75 non-
# English entries doesn't print the same warning 75 times.
_warned_missing_package = False
_warned_missing_model = set()


def _warn_missing_package():
    global _warned_missing_package
    if not _warned_missing_package:
        print(
            "[WARN] translation: argostranslate not installed - non-English "
            "entries will keep their original-language text only. Install "
            "with: pip install -r requirements-translation.txt"
        )
        _warned_missing_package = True


def _warn_missing_model(lang):
    if lang not in _warned_missing_model:
        print(
            f"[WARN] translation: no {lang}->en model installed - entries in "
            f"this language will keep their original-language text only. "
            f"Install models with: "
            f"python scripts/maintenance/install_translation_models.py"
        )
        _warned_missing_model.add(lang)


def translate_text(text, source_lang, target_lang="en"):
    """
    Translate `text` from source_lang to target_lang.

    Returns the translated string, or None if translation isn't available
    (package/model not installed) or fails on this particular text. Never
    raises - callers keep the original text when this returns None.
    """
    if not text:
        return None

    if not TRANSLATION_AVAILABLE:
        _warn_missing_package()
        return None

    try:
        installed = argostranslate.translate.get_installed_languages()
        from_lang = next((l for l in installed if l.code == source_lang), None)
        to_lang = next((l for l in installed if l.code == target_lang), None)

        if not from_lang or not to_lang:
            _warn_missing_model(source_lang)
            return None

        return from_lang.get_translation(to_lang).translate(text)

    except Exception as e:
        # A transient/per-entry failure (corrupt model state, unexpected
        # input, etc.) must not take down a whole scrape/backfill run - log
        # it clearly and let the caller keep the original text.
        print(
            f"[WARN] translation: failed to translate {source_lang}->"
            f"{target_lang} text ({len(text)} chars): {e}"
        )
        return None


def translate_threat_fields(title, description, source_language):
    """
    Translate title/description of a single threat entry per the
    language's field policy (FIELDS_TO_TRANSLATE).

    Returns {"title_translated", "description_translated", "translated_at"},
    matching the threats table columns - suitable for spreading directly
    into an INSERT/UPDATE. translated_at is only set if at least one field
    was actually translated (stays None for English-native entries, entries
    in a language we don't have a policy for, or entries where translation
    was attempted but failed for every eligible field).
    """
    result = {"title_translated": None, "description_translated": None, "translated_at": None}

    fields = FIELDS_TO_TRANSLATE.get(source_language)
    if not fields:
        return result

    if "title" in fields:
        result["title_translated"] = translate_text(title, source_language)
    if "description" in fields:
        result["description_translated"] = translate_text(description, source_language)

    if result["title_translated"] or result["description_translated"]:
        result["translated_at"] = datetime.now().isoformat()

    return result
