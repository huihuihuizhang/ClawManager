import axios from 'axios';
import api from './api';
import { createBackupApiReadClient } from '../pages/admin/backups/backupApiRead';

// Use the application's existing token and refresh interceptors. The page
// chooses when to activate this service after the read permission is wired.
export const systemBackupReadService = createBackupApiReadClient(async (path, signal) => {
  if (!path.startsWith('/api/v1/admin/system-')) throw new Error('Unexpected system backup read path');
  const endpoint = path.slice('/api/v1'.length);
  try {
    const response = await api.get(endpoint, { signal });
    return new Response(JSON.stringify(response.data), {
      status: response.status,
      headers: {
        'X-System-Backup-Data-Source': String(response.headers['x-system-backup-data-source'] ?? ''),
        'X-System-Backup-Origin-Installation-ID': String(response.headers['x-system-backup-origin-installation-id'] ?? ''),
        'X-System-Backup-Task-Row-Version': String(response.headers['x-system-backup-task-row-version'] ?? ''),
      },
    });
  } catch (error) {
    if (!axios.isAxiosError(error) || !error.response) throw error;
    return new Response(JSON.stringify(error.response.data), {
      status: error.response.status,
      headers: { 'X-System-Backup-Data-Source': String(error.response.headers['x-system-backup-data-source'] ?? '') },
    });
  }
});
