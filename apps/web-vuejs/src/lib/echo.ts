import Echo from 'laravel-echo';
import Pusher from 'pusher-js';

let echoInstance: Echo<'pusher'> | null = null;

export function getEcho(): Echo<'pusher'> {
  if (echoInstance) return echoInstance;

  const key = import.meta.env.VITE_REVERB_APP_KEY;
  const host = import.meta.env.VITE_REVERB_HOST;
  const port = Number(import.meta.env.VITE_REVERB_PORT);

  if (!key) {
    throw new Error('VITE_REVERB_APP_KEY is not defined — restart the Vite dev server');
  }

  // Make Pusher available globally (required by laravel-echo)
  (window as unknown as Record<string, unknown>).Pusher = Pusher;

  echoInstance = new Echo({
    broadcaster: 'pusher',
    key,
    wsHost: host,
    wsPort: port,
    forceTLS: false,
    disableStats: true,
    enabledTransports: ['ws'],
    cluster: '',
  });

  return echoInstance;
}
