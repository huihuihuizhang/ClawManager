import { useCallback } from 'react';
import { useI18n } from '../../../contexts/I18nContext';
import { backupLocaleTags, formatBackupDate, systemBackupTranslations } from '../../../lib/systemBackupI18n';
import type { BackupTextKey } from '../../../lib/systemBackupI18n';
import { interpolate } from '../../../lib/i18n';

export function useBackupText() {
  const { locale } = useI18n();
  const b = useCallback((key: BackupTextKey, variables?: Record<string, string | number>) => interpolate(systemBackupTranslations[locale]?.[key] ?? systemBackupTranslations.en[key], variables), [locale]);
  const label = (value: string) => {
    const key = `status_${value}` as BackupTextKey;
    return Object.hasOwn(systemBackupTranslations.en, key) ? b(key) : value;
  };
  return {
    b, label,
    locale: backupLocaleTags[locale],
    date: (value: string) => formatBackupDate(value, locale),
    number: (value: number) => new Intl.NumberFormat(backupLocaleTags[locale]).format(value),
    list: (values: string[]) => new Intl.ListFormat(backupLocaleTags[locale], { style: 'long', type: 'conjunction' }).format(values),
  };
}
