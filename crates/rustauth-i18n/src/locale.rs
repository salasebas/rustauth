//! Locale lookup and validation for i18n dictionaries.

use std::collections::HashMap;

use indexmap::IndexMap;

use crate::error::I18nConfigError;
use crate::types::TranslationDictionary;

#[derive(Debug, Clone)]
pub(crate) struct LocaleCatalog {
    canonical_by_normalized: HashMap<String, String>,
}

impl LocaleCatalog {
    pub(crate) fn new(
        translations: &IndexMap<String, TranslationDictionary>,
    ) -> Result<Self, I18nConfigError> {
        if translations.is_empty() {
            return Err(I18nConfigError::EmptyTranslations);
        }

        let mut canonical_by_normalized = HashMap::with_capacity(translations.len());
        for locale in translations.keys() {
            let normalized = normalize_locale(locale);
            if canonical_by_normalized
                .insert(normalized, locale.clone())
                .is_some()
            {
                return Err(I18nConfigError::DuplicateLocale(locale.clone()));
            }
        }

        Ok(Self {
            canonical_by_normalized,
        })
    }

    pub(crate) fn match_locale(&self, candidate: &str) -> Option<&str> {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            return None;
        }

        let normalized = normalize_locale(trimmed);
        if let Some(locale) = self.canonical_by_normalized.get(&normalized) {
            return Some(locale.as_str());
        }

        let base = trimmed.split_once('-')?.0;
        let normalized_base = normalize_locale(base);
        self.canonical_by_normalized
            .get(&normalized_base)
            .map(String::as_str)
    }
}

fn normalize_locale(locale: &str) -> String {
    locale.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn translations(locales: &[&str]) -> IndexMap<String, TranslationDictionary> {
        locales
            .iter()
            .map(|locale| ((*locale).to_owned(), TranslationDictionary::new()))
            .collect()
    }

    #[test]
    fn match_locale_prefers_exact_region_before_base() -> Result<(), I18nConfigError> {
        let catalog = LocaleCatalog::new(&translations(&["pt", "pt-BR"]))?;

        assert_eq!(catalog.match_locale("pt-BR"), Some("pt-BR"));
        Ok(())
    }

    #[test]
    fn match_locale_falls_back_to_base_locale() -> Result<(), I18nConfigError> {
        let catalog = LocaleCatalog::new(&translations(&["fr"]))?;

        assert_eq!(catalog.match_locale("fr-CA"), Some("fr"));
        Ok(())
    }

    #[test]
    fn match_locale_is_case_insensitive() -> Result<(), I18nConfigError> {
        let catalog = LocaleCatalog::new(&translations(&["fr"]))?;

        assert_eq!(catalog.match_locale("FR-ca"), Some("fr"));
        Ok(())
    }

    #[test]
    fn duplicate_locale_after_normalization_is_rejected() {
        assert!(matches!(
            LocaleCatalog::new(&translations(&["en", "EN"])),
            Err(I18nConfigError::DuplicateLocale(locale)) if locale == "EN"
        ));
    }
}
