import { createI18n } from 'vue-i18n'
import fr from './fr'
import en from './en'

export type MessageSchema = typeof fr

const STORAGE_KEY = 'tilvest_locale'

// Obtenir la langue stockée ou détecter depuis le navigateur
function getStoredLocale(): 'en' | 'fr' {
  if (typeof localStorage === 'undefined') return 'fr'

  const stored = localStorage.getItem(STORAGE_KEY)
  if (stored && (stored === 'en' || stored === 'fr')) return stored

  // Détecter depuis le navigateur
  const browserLang = navigator.language?.split('-')?.[0]
  return browserLang === 'en' || browserLang === 'fr' ? browserLang : 'fr'
}

// Sauvegarder la langue
export function setLocale(locale: 'en' | 'fr') {
  if (typeof localStorage !== 'undefined') {
    localStorage.setItem(STORAGE_KEY, locale)
  }
}

const i18n = createI18n<[MessageSchema], 'en' | 'fr'>({
  legacy: false,
  locale: getStoredLocale(),
  fallbackLocale: 'fr',
  messages: {
    en,
    fr,
  },
})

export default i18n
