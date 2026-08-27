"""
Unit tests for core/translation.py (Argos Translate wrapper - Vague 3a).

The real argostranslate package and downloaded models are NOT required for
this suite: argostranslate is mocked throughout, patched onto
core.translation.argostranslate with create=True so it works whether or not
the optional package is actually installed (see requirements-translation.txt
- it isn't in requirements.txt). Real end-to-end translation quality is
checked separately via the @pytest.mark.integration tests below (excluded
by default - see pytest.ini - run with `pytest -m integration`; requires
`pip install -r requirements-translation.txt` and the models installed via
scripts/maintenance/install_translation_models.py).
"""

import unittest
from unittest.mock import MagicMock, patch

import pytest

import core.translation as translation


def _fake_lang(code):
    lang = MagicMock()
    lang.code = code
    return lang


def _mock_argos(installed_codes, translate_fn=None):
    """MagicMock standing in for the argostranslate module: get_installed_languages()
    returns one fake Language per code, whose get_translation(to).translate(text)
    is driven by translate_fn (default: prefixes with 'EN: ')."""
    translate_fn = translate_fn or (lambda text: f"EN: {text}")

    langs = []
    for code in installed_codes:
        lang = _fake_lang(code)
        translation_obj = MagicMock()
        translation_obj.translate.side_effect = translate_fn
        lang.get_translation.return_value = translation_obj
        langs.append(lang)

    argos = MagicMock()
    argos.translate.get_installed_languages.return_value = langs
    return argos


class TestTranslateText(unittest.TestCase):

    def test_returns_none_when_package_unavailable(self):
        with patch.object(translation, "TRANSLATION_AVAILABLE", False):
            result = translation.translate_text("bonjour", "fr")
        self.assertIsNone(result)

    def test_returns_none_for_empty_text(self):
        self.assertIsNone(translation.translate_text("", "fr"))
        self.assertIsNone(translation.translate_text(None, "fr"))

    def test_translates_when_model_installed(self):
        mock_argos = _mock_argos(["fr", "en"])
        with patch.object(translation, "TRANSLATION_AVAILABLE", True), \
             patch.object(translation, "argostranslate", mock_argos, create=True):
            result = translation.translate_text("bonjour", "fr")
        self.assertEqual(result, "EN: bonjour")

    def test_returns_none_when_model_not_installed(self):
        mock_argos = _mock_argos(["ru", "en"])  # fr model missing
        with patch.object(translation, "TRANSLATION_AVAILABLE", True), \
             patch.object(translation, "argostranslate", mock_argos, create=True):
            result = translation.translate_text("bonjour", "fr")
        self.assertIsNone(result)

    def test_returns_none_and_does_not_raise_on_translation_failure(self):
        """A transient/per-entry failure must not propagate - the caller
        keeps the original text instead of the whole run crashing."""
        broken_lang = _fake_lang("fr")
        broken_lang.get_translation.side_effect = RuntimeError("simulated engine failure")
        mock_argos = MagicMock()
        mock_argos.translate.get_installed_languages.return_value = [broken_lang, _fake_lang("en")]

        with patch.object(translation, "TRANSLATION_AVAILABLE", True), \
             patch.object(translation, "argostranslate", mock_argos, create=True):
            result = translation.translate_text("bonjour", "fr")
        self.assertIsNone(result)


class TestTranslateThreatFields(unittest.TestCase):

    def setUp(self):
        mock_argos = _mock_argos(["zh", "ru", "fr", "en"])
        for target, value in [("TRANSLATION_AVAILABLE", True), ("argostranslate", mock_argos)]:
            patcher = patch.object(translation, target, value, create=(target == "argostranslate"))
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_zh_translates_description_only_not_title(self):
        """Real quality issue found on live CNVD data (Vague 3a diagnostic):
        the model drops security-critical detail from short zh titles, so
        titles are deliberately excluded from FIELDS_TO_TRANSLATE for zh."""
        result = translation.translate_threat_fields("中文标题", "中文描述", "zh")
        self.assertIsNone(result["title_translated"])
        self.assertEqual(result["description_translated"], "EN: 中文描述")
        self.assertIsNotNone(result["translated_at"])

    def test_ru_translates_both_fields(self):
        result = translation.translate_threat_fields("Русский заголовок", "Русское описание", "ru")
        self.assertEqual(result["title_translated"], "EN: Русский заголовок")
        self.assertEqual(result["description_translated"], "EN: Русское описание")
        self.assertIsNotNone(result["translated_at"])

    def test_fr_translates_both_fields(self):
        result = translation.translate_threat_fields("Titre français", "Description française", "fr")
        self.assertEqual(result["title_translated"], "EN: Titre français")
        self.assertEqual(result["description_translated"], "EN: Description française")
        self.assertIsNotNone(result["translated_at"])

    def test_unknown_language_translates_nothing(self):
        result = translation.translate_threat_fields("Titel", "Beschreibung", "de")
        self.assertIsNone(result["title_translated"])
        self.assertIsNone(result["description_translated"])
        self.assertIsNone(result["translated_at"])

    def test_english_native_source_translates_nothing(self):
        """source_language is None for English-native sources (NVD, GitHub, JVN...)"""
        result = translation.translate_threat_fields("Some title", "Some description", None)
        self.assertIsNone(result["title_translated"])
        self.assertIsNone(result["description_translated"])
        self.assertIsNone(result["translated_at"])

    def test_translated_at_stays_none_when_every_eligible_field_fails(self):
        empty_argos = MagicMock()
        empty_argos.translate.get_installed_languages.return_value = []  # no models installed
        with patch.object(translation, "argostranslate", empty_argos, create=True):
            result = translation.translate_threat_fields("Titre", "Description", "fr")
        self.assertIsNone(result["title_translated"])
        self.assertIsNone(result["description_translated"])
        self.assertIsNone(result["translated_at"])


class TestRealTranslation(unittest.TestCase):
    """Real translation using the actual argostranslate package and downloaded
    models - run with: pytest -m integration. Requires
    `pip install -r requirements-translation.txt` and models installed via
    scripts/maintenance/install_translation_models.py."""

    def setUp(self):
        if not translation.TRANSLATION_AVAILABLE:
            self.skipTest("argostranslate not installed - pip install -r requirements-translation.txt")

    @pytest.mark.integration
    def test_real_fr_translation(self):
        result = translation.translate_text("Vulnérabilité critique découverte", "fr")
        self.assertIsInstance(result, str)
        self.assertIn("vulnerab", result.lower())

    @pytest.mark.integration
    def test_real_zh_translates_description_not_title(self):
        result = translation.translate_threat_fields(
            "标题", "该漏洞可能导致远程代码执行。", "zh"
        )
        self.assertIsNone(result["title_translated"])
        self.assertIsInstance(result["description_translated"], str)

    @pytest.mark.integration
    def test_real_ru_translation(self):
        result = translation.translate_text("Уязвимость позволяет выполнить произвольный код", "ru")
        self.assertIsInstance(result, str)
        self.assertIn("code", result.lower())


if __name__ == "__main__":
    unittest.main()
